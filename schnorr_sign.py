import argparse
import json
import sys

from schnorr_lib import sha256, schnorr_sign, schnorr_verify, schnorr_musig_sign, schnorr_musig_verify, bytes_from_hex


def main():
    parser = argparse.ArgumentParser(
        description='returns the signature and the public key from a private key and a message')
    parser.add_argument('-m', '--message', type=str, required=True, help='Message')
    parser.add_argument('--musig', action='store_true', help="Use musig")
    args = parser.parse_args()
    msg = args.message
    musig = args.musig  # Flag

    # Get message digest
    try:
        M = sha256(msg.encode())
    except Exception:
        print("[e] Error. Message should be defined")
        sys.exit(2)

    # Get keypair
    try:
        keypairs = json.load(open("keypairs.json", "r"))
    except Exception:
        print("[e] Error. File nonexistent")
        sys.exit(2)

    # Signature
    try:
        if not musig:
            sig = schnorr_sign(M, keypairs)
            result = schnorr_verify(M, bytes_from_hex(
                keypairs["keypairs"][0]["publicKey"]), sig)
            print('> Message =', M.hex())
            print("> Signature =", sig.hex())
            print(">>> Is the signature right?", result)
        elif musig:
            Rsum, ssum, X = schnorr_musig_sign(M, keypairs)
            result = schnorr_musig_verify(M, Rsum, ssum, X)
            print('> Message =', M.hex())
            print("> Signature =", Rsum, ssum)
            print(">>> Is the signature right?", result)
    except Exception:
        print("[e] Error. Number of keys should be defined")
        sys.exit(2)


if __name__ == "__main__":
    main()
