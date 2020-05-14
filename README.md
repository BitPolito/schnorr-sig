# Schorr Signatures

This is a Schnorr signatures utility for educational purposes only.

There are four scripts:

- `schnorr.py`: is the BIP340 reference implementation minimally changed to perform a test from the `test-vector.csv`; see <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki> and the reference implementation at <https://github.com/bitcoin/bips/tree/master/bip-0340>
- `create_priv_key.py`: asks for a sentence (no newline characters), SAH256-hashes it and creates a key pair which can be use to `schnorr-sign` and `schnorr-verify` a message.
- `schnorr-sign.py`: from a private key and a message, the scripts returns the signature and the public key
- `schnorr-verify.py`: from a public key, a message and a signature, the script returns `True` or `False`

Both the scripts `schnorr-sign.py` and `schnorr-verify.py` are taken from the reference implementation. 

I created the `create_priv_key.py`, but should not be used in production environments because it is not secure enough. 
