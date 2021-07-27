# Schnorr Signatures

This is a **Schnorr signatures utility** for *educational purposes* only, developed by Fadi Barbara ([@disnocen](https://github.com/disnocen)) and published by BIT PoliTO.

## Scripts

There are four scripts:

- ##### Schnorr tester
`schnorr.py`: is the BIP340 reference implementation minimally changed to perform a test from the `test-vector.csv`; see <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki> and the reference implementation at <https://github.com/bitcoin/bips/tree/master/bip-0340>.

- ##### Private key creator
`create_priv_key.py`: asks for a sentence (no newline characters), SAH256-hashes it and creates a key pair which can be use to `schnorr-sign` and `schnorr-verify` a message.

- ##### Schnorr signer
`schnorr-sign.py`: from a private key and a message, the scripts returns the signature and the public key; see `python3 schnorr-sign.py -h` for the syntax.

- ##### Schnorr verifier
`schnorr-verify.py`: from a public key, a message and a signature, the script returns `True` or `False`; see `python3 schnorr-verify.py -h` for the syntax.

Both the scripts `schnorr-sign.py` and `schnorr-verify.py` are taken from the reference implementation. 

I created the `create_priv_key.py`, but should not be used in production environments because it is not secure enough.

The functions used in those scripts are collected in the library `schnorrlib.py`.

## How to install and run code
### Installation

```console
# clone the repo
$ git clone https://github.com/BITPoliTO/schnorr-sig.git

# change the working directory to schnorr-sig
$ cd schnorr-sig

# install general requirements
$ pip install typing 
$ pip install hashlib
```

### Run
```console
$ python create_priv_key.py
$ python schnorr-sign.py -s <private_key> -m <message>
$ python schnorr-verify.py -s <signature> -p <public_key> -m <message>
```

#### Made to educate the BIT PoliTO team 🎓 by  
  
<a href="https://github.com/BITPoliTO/schnorr-sig/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=bitpolito/schnorr-sig" />
</a>