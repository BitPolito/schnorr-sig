# Schnorr Signatures

This is a **Schnorr signatures utility** for *educational purposes* only, developed by Fadi Barbara ([@disnocen](https://github.com/disnocen)) and published by BIT PoliTO in Python3.

## Scripts

There are four scripts:

- #### Key pair creator
`create_keypair.py` asks for a sentence (no newline characters), SHA256 hashes it and then creates a key pair which can be used to `schnorr_sign` and `schnorr_verify` a message.

- #### Schnorr signer
`schnorr_sign.py` returns the signature and the public key from a private key and a message. <br>
See `python schnorr_sign.py -h` for the syntax.

- #### Schnorr verifier
`schnorr_verify.py` returns `True` or `False` from a public key, a message and a signature. <br>
See `python schnorr_verify.py -h` for the syntax.

- #### Schnorr tester
`schnorr_test.py` is the BIP340 reference implementation minimally changed to perform a test from the `test-vector.csv`. <br>
See <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki> and the reference implementation at <https://github.com/bitcoin/bips/tree/master/bip-0340>.

Both the scripts `schnorr_sign.py` and `schnorr_verify.py` are taken from the reference implementation. 

The script `create_keypair.py` should not be used in production environments because it is not secure enough.

The functions used in those scripts are collected in the library `schnorr_lib.py`.

## How to install and run code
### Installation

```console
# clone the repo
$ git clone https://github.com/BITPoliTO/schnorr-sig.git

# change the working directory to schnorr-sig
$ cd schnorr-sig

# install general requirements
$ pip install typing 
```

### Run
```console
$ python create_keypair.py
$ python schnorr_sign.py -s <secret_key> -m <message>
$ python schnorr_verify.py -s <signature> -p <public_key> -m <message>
```

#### Made to educate the BIT PoliTO team 🎓 by  
  
<a href="https://github.com/BITPoliTO/schnorr-sig/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=bitpolito/schnorr-sig" />
</a>
