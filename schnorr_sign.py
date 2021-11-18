import argparse
import json
import sys

from schnorr_lib import sha256, schnorr_sign, schnorr_verify, schnorr_musig_sign, schnorr_musig2_sign, schnorr_musig_verify, bytes_from_hex


def main():
    parser = argparse.ArgumentParser(
        description='returns the signature and the public key from a private key and a message')
    parser.add_argument('-m', '--message', type=str, required=True, help='Message')
    parser.add_argument('--musig1', action='store_true', help="Use MuSig-1")
    parser.add_argument('--musig2', action='store_true', help="Use MuSig-2")
    
    args = parser.parse_args()
    msg = args.message
    musig1 = args.musig1 # Flag
    musig2 = args.musig2 # Flag

    # Get message digest
    try:
        M = sha256(msg.encode())
    except Exception:
        print("[e] Error. Message should be defined")
        sys.exit(2)

    # Get keypair
    try:
        users = json.load(open("users.json", "r"))["users"]
    except Exception:
        print("[e] Error. File nonexistent")
        sys.exit(2)

    # Signature
    try:
        if not ( musig1 or musig2):
            sig = schnorr_sign(M, users[0])
            result = schnorr_verify(M, bytes_from_hex(
                users[0]["publicKey"]), sig)
            print('> Message =', M.hex())
            print("> Signature =", sig.hex())
            print(">>> Is the signature right?", result)
        elif musig1:
            Rsum, ssum, X = schnorr_musig_sign(M, users)
            result = schnorr_musig_verify(M, Rsum, ssum, X)
            print('> Message =', M.hex())
            print("> Signature =", Rsum, ssum)
            print(">>> Is the signature right?", result)
        elif musig2:
            Rsum, ssum, X = schnorr_musig2_sign(M, users)
            result = schnorr_musig_verify(M, Rsum, ssum, X)
            print('> Message =', M.hex())
            print("> Signature =", Rsum, ssum)
            print(">>> Is the signature right?", result)
    except Exception:
        print("[e] Error. Number of keys should be defined")
        sys.exit(2)


if __name__ == "__main__":
    main()
