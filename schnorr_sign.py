import argparse
import json
import sys

from schnorr_lib import sha256, schnorr_sign, schnorr_verify, schnorr_musig_sign, schnorr_musig2_sign, schnorr_musig_verify, bytes_from_hex


def main():
    parser = argparse.ArgumentParser(
        description='returns the signature and the public key from a private key and a message')
    parser.add_argument('-m', '--message', type=str, required=True, help='Message to be signed')
    parser.add_argument('-i','--index', type=int, help="When single signing, by passing this argument the index of the keypair to use is specified otherwise the first will be used by default")
    parser.add_argument('--musig1', action='store_true', help="Use MuSig-1")
    parser.add_argument('--musig2', action='store_true', help="Use MuSig-2")
    
    args = parser.parse_args()
    msg = args.message
    musig1 = args.musig1 # Flag
    musig2 = args.musig2 # Flag

    i = 0 # default value for single signing
    if args.index:
        i = args.index


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
        print("[e] Error. File nonexistent, create it with create_keypair.py")
        sys.exit(2)
      
    # Signature
    try:    
        if not ( musig1 or musig2 ):
            if i < 0 or i >= len(users):
                print("[e] Error. The index is out of range")
                sys.exit(2)
            sig = schnorr_sign(M, users[i])
            print("> Message =", M.hex())
            print("> Signature =", sig.hex())
        elif musig1:
            sig, X = schnorr_musig_sign(M, users)
            print("> Message =", M.hex())
            print("> Signature =", sig.hex())
            print("> Public aggregate=", X.hex())
        elif musig2:
            sig, X = schnorr_musig2_sign(M, users)
            print("> Message =", M.hex())
            print("> Signature =", sig.hex())
            print("> Public aggregate=", X.hex())
        
    except Exception as e:
            print("[e] Exception: \n", e)
            sys.exit(2)


if __name__ == "__main__":
    main()
