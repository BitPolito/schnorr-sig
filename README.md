# Schnorr Signatures

[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/BITPoliTO/schnorr-sig.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/BITPoliTO/schnorr-sig/context:python)

This is a **Schnorr Signatures** utility for *educational purposes* only, developed by [BitPolito](https://www.bitpolito.it) in Python3.

The classic signature and verification functions are based on the [BIP340 reference implementation](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki), while we tried to keep as close as possible to it the MuSig functions, even if they are not specified (yet).

### Main authors
[Alessandro Guggino](https://github.com/alessandroguggino), [Luca Giorgino](https://github.com/lucagiorgino), [Andrea Gangemi](https://github.com/Gangi94), [Fadi Barbara](https://github.com/disnocen).

## Scripts

There are four main scripts:

- #### Key pair creator
`create_keypair.py` creates one or more key pairs which are stored in a JSON file and can be used to sign and verify a message. <br>
**Syntax**: `create_keypair.py -n <number of keys>`

- #### Schnorr signer
`schnorr_sign.py` returns the signature from one or more private keys and a message. <br>
**Syntax**: `schnorr_sign.py [--musig1 || --musig2] (optional) -m <message>`

- #### Schnorr verifier
`schnorr_verify.py` returns `True` or `False` from a signature, a single public key or an aggregated one, and a message. <br>
**Syntax**: `schnorr_verify.py -s <signature> -p <public_key> -m <message>`

- #### Schnorr tester
`schnorr_test.py` is the BIP340 reference implementation minimally changed to perform a test from the [test vectors](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).

**Note:** All the functions used in those scripts are collected in the library `schnorr_lib.py`.

## How to install and run code
We used Python3 to write these scripts.

### Installation
```console
# clone the repo
$ git clone https://github.com/BITPoliTO/schnorr-sig.git

# change the working directory to schnorr-sig
$ cd schnorr-sig
```

### Usage
```console
$ python create_keypair.py -n <number_of_keys>
$ python schnorr_sign.py [--musig1 || --musig2] (optional) -m <message>
$ python schnorr_verify.py -s <signature> -p <public_key> -m <message>
```

## Jupyter
The code can also be launched from a Jupyter Notebook, thanks to the script collected in the library "schnorr.ipynb".
```console
# Download Jupyter Notebook
$ pip install notebook

# Launch
$ python -m notebook
```

Select `schnorr.ipynb` from your folders and enjoy! You can:
- generate your own keypairs;
- generate a Schnorr, MuSig1 or MuSig2 signature;
- check that the obtained signature is valid.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Contributors
<a href="https://github.com/BITPoliTO/schnorr-sig/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=BITPoliTO/schnorr-sig" />
</a>
