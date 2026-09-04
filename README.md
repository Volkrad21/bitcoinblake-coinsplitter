# bitcoinblake-coinsplitter

A small, dependency-free Python utility that constructs an unsigned Bitcoin
PSBT containing a deliberately oversized `OP_RETURN` output. It never handles
private keys, signs transactions, or broadcasts transactions.

## Important

This is experimental software. Independently verify the current consensus and
mempool rules on both Bitcoin and Bitcoin Blake before using it with funds.
Review every generated PSBT in a trusted signer and test the final transaction
with Bitcoin Core's `testmempoolaccept` before broadcasting.

The embedded marker is 96 bytes of project-specific binary data. Including the
push opcode, the marker script is 99 bytes. The marker is public and makes
transactions created by this release recognizable as belonging to this tool.
It is intentionally unrelated to markers used by earlier tools, but that does
not guarantee transaction privacy: reused addresses, common inputs, amounts,
output ordering, fee choice, and broadcast timing can all link transactions.

## Requirements

- Python 3.10 or newer
- A native SegWit P2WPKH input
- A fresh P2WPKH, P2WSH, or P2TR destination address

## Usage

```console
python bitcoinblake_coinsplitter.py
```

The program asks for a complete raw parent transaction, its output index, a
fresh destination address, and a fee rate. After confirmation it writes:

- `unsigned_transaction.txt`
- `transaction.psbt`
- `transaction_psbt_base64.txt`

These generated files are excluded by `.gitignore`.

## Privacy

Do not reuse the source address or destination address. For stronger separation
from previous activity, also avoid shared inputs, distinctive round amounts,
identical fee rates, and closely correlated broadcast times. Publishing this
repository necessarily makes its new marker attributable to this project.

## License

MIT
