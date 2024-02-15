

# Bitcoin Transaction Analyzer and Private Key Recovery

**This Python project helps analyze Bitcoin transactions associated with an address and attempts to recover potential private keys through the analysis of ECDSA signatures used in the transactions.**

## Key Features

* **Transaction Data Retrieval:** Fetches details of transactions (input/output) associated with a specified Bitcoin address from mempool.space.  
* **ECDSA Signature Extraction:** Parses raw transaction data to extract the 'r', 's', and 'z' components of ECDSA signatures.
* **Duplicate-R Detection:** Identifies transactions that reuse the 'R' value within ECDSA signatures. Reusing 'R' is a security weakness.
* **Private Key Recovery Attempt:** Applies a mathematical approach (BSGS algorithm) to the extracted data in an attempt to calculate the private key (if the duplicate-R vulnerability exists).

## Prerequisites

* Python 3.6 or later
* **Dependencies:**
   * `requests`
   * `json`
   * `hashlib`
   * `secp256k1` (`pip install secp256k1`)

## Installation

```bash
1. Clone this repository:
   git clone [https://github.com/your-username/bitcoin-tx-analyzer](https://github.com/your-username/bitcoin-tx-analyzer)

2. Install the required dependencies:
   cd bitcoin-tx-analyzer
   pip install -r requirements.txt 
```
## Usage

```bash
1. Create a text file (e.g., `addresses.txt`) containing the Bitcoin addresses you want to analyze, with one address per line.

2. Execute the script:
   python main.py -f addresses.txt
```
i have added a sample file with about 1 million legacy address i am not sure are all addresses legacy so if u got error in any address just delete it from file

## Script Output

* **For each address:** 
* Relevant transaction details, including transaction IDs (txid).
* Values of 'r', 's', and 'z' from ECDSA signatures for each transaction.
* Indications of transactions with duplicate 'R' values.
* If private key recovery is successful, the calculated private key will be printed.
* **All recovered private keys are saved to a file named `private_keys.txt`.**

## Important Notes

* Success in recovering private keys depends on the existence of transactions using duplicate 'R' values. This scenario is possible due to certain weaknesses in implementations of ECDSA or random number generators.
* Use this tool for educational and security research purposes.

## Contributing
Contributions are welcome to enhance functionality or fix issues. Please submit a pull request with your proposed changes.

## Contact
If you have questions or feedback, feel free to open an issue in this repository.
License:

MIT License (see LICENSE file)



