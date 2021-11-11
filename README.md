# Schnorr Signatures

This is a **Schnorr signatures utility** for *educational purposes* only, developed by BIT PoliTO in Python3.

The classic signature and verification functions are developed from the BIP340 reference implementation, while we tried to keep as close as possible to it the MuSig functions, even if they are not specified (yet).

## Scripts

There are four main scripts:

- #### Key pair creator
`create_keypair.py` creates one or more key pairs which are stored in a JSON file and can be used to sign and verify a message.
**Syntax**: `create_keypair.py -n <number of keys>`

- #### Schnorr signer
`schnorr_sign.py` returns the signature from one or more private keys and a message. <br>
**Syntax**: `schnorr_sign.py --musig (optional) -m <message>`

- #### Schnorr verifier
`schnorr_verify.py` returns `True` or `False` from a signature, a single public key or an aggregated one, and a message. <br>
**Syntax**: `schnorr_verify.py -s <signature> -p <public_key> -m <message>`

- #### Schnorr tester
`schnorr_test.py` is the BIP340 reference implementation minimally changed to perform a test from the `test-vector.csv`. <br>
See <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki> and the reference implementation at <https://github.com/bitcoin/bips/tree/master/bip-0340>.

All the functions used in those scripts are collected in the library `schnorr_lib.py`.

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

### Usage
```console
$ python3 create_keypair.py -n <number_of_keys>
$ python3 schnorr_sign.py --musig (optional) -m <message>
$ python3 schnorr_verify.py -s <signature> -p <public_key> -m <message>
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

#### Made to educate the BIT PoliTO team 🎓 by  
  
<a href="https://github.com/BITPoliTO/schnorr-sig/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=BITPoliTO/schnorr-sig" />
</a>
