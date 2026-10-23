# RSZ-Scanner

RSZ-Scanner inspects Bitcoin transactions for ECDSA signatures with repeated or related nonces. When it finds a candidate, it calculates a possible private key and verifies it against the public key from the signatures before saving it.

## Features

- Fetches address transaction data from mempool.space, with Blockstream as a transaction lookup fallback.
- Parses legacy and supported SegWit inputs and builds signature message hashes.
- Searches for repeated or related ECDSA nonces.
- Verifies recovered key candidates against the public key before writing them.
- Shows address-by-address progress and prints a run summary.
- Lets you configure HTTP timeouts, retry attempts, retry backoff, and the output file.

## Requirements

- Python 3.6 or later
- The `secp256k1.py` wrapper and compatible native library included in this repository
- Python packages listed in `requirements.txt`

Install the listed packages with:

```bash
python -m pip install -r requirements.txt
```

## Prepare addresses

Create a UTF-8 text file with one Bitcoin address per line. Blank lines are ignored. Addresses with no matching transaction inputs are reported and skipped. The scanner can skip inputs it cannot parse or does not support.

## Run

```bash
python main.py --file addresses.txt
```

This uses the defaults: 20 seconds per HTTP request, 3 attempts per request, a 1.5 retry-delay multiplier, and `private_keys.txt` as the output file.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `-f`, `--file` | Required | Text file containing one address per line |
| `-o`, `--output` | `private_keys.txt` | File to append verified keys to |
| `--timeout` | `20` | HTTP timeout in seconds |
| `--retries` | `3` | Maximum attempts for each HTTP request |
| `--retry-backoff` | `1.5` | Multiplier applied to the delay between retry attempts |

For example, to use a different output file and retry configuration:

```bash
python main.py -f addresses.txt -o recovered_keys.txt --timeout 30 --retries 5 --retry-backoff 2
```

The output file is opened in append mode. Each saved line contains the address and its verified private key. Protect this file as sensitive data.

## Progress and summary

The program prints a progress line for each non-empty address. At completion, its summary reports the number of addresses in the file, addresses processed, failures, addresses without transactions, addresses without a recovery candidate, verified keys recovered, and keys saved. If interrupted, it prints a partial summary.

## Limitations

Recovery only succeeds when the transaction signatures expose a nonce relationship the scanner can identify. Unsupported scripts and malformed inputs may be skipped. Network access to the transaction data providers is required.

Use this tool only for addresses and data you are authorized to analyze, such as your own wallets or controlled test data.

## License

MIT License. See [LICENSE](LICENSE).
