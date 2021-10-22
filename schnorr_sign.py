from schnorr_lib import sha256, schnorr_sign, schnorr_verify, schnorr_musig_sign, schnorr_musig_verify, bytes_from_hex
import sys, getopt, json


def main(argv):

    try:
        opts, args = getopt.getopt(argv, "hn:m:", ["nkeys=", "msg="])
    except getopt.GetoptError:
        print('[i] Command not found. Type -h for help')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print('[i] Command: schnorr_sign.py -n <number_of_keys> -m <message>')
            sys.exit()
        elif opt in ("-n", "--nkeys"):
            if arg.isnumeric():
                n_keys = int(arg)
            else:
                print('[i] Number needed. Type -h for help ')
                sys.exit(2)
        elif opt in ("-m", "--msg"):
            msg = arg

    if not opts:
        print('[i] Argument needed. Type -h for help ')
        sys.exit(2)

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
        if n_keys == 1:
            sig = schnorr_sign(M, keypairs)
            result = schnorr_verify(M, bytes_from_hex(
            keypairs["keypairs"][0]["publicKey"]), sig)
            print('> Message =', M.hex())
            print("> Signature =", sig.hex())
            print(">>> Is the signature right?", result)
        elif n_keys > 1:
            Rsum, ssum, X = schnorr_musig_sign(M, keypairs)
            result = schnorr_musig_verify(M, Rsum, ssum, X)
            print('> Message =', M.hex())
            print("> Signature =", Rsum, ssum)
            print(">>> Is the signature right?", result)
    except Exception:
        print("[e] Error. Number of keys should be defined")
        sys.exit(2)


if __name__ == "__main__":
   main(sys.argv[1:])

