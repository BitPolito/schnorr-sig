from schnorrlib import schnorr_verify, hash_sha256
import sys, getopt

def main(argv):
    pubkey = ''
    msg = ''
    sig = ''
    try:
        opts, args = getopt.getopt(argv, "hs:p:m:", ["sig=", "pk=", "msg="])
    except getopt.GetoptError:
        print('schnorr-verify.py -s <hex_signature> -p <hex_publickey> -m <message>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('schnorr-verify.py -s <hex_signature> -p <hex_publickey> -m <message>')
            sys.exit()
        elif opt in ("-p", "--pk"):
            pubkey = arg
        elif opt in ("-s", "--sig"):
            sig = arg
        elif opt in ("-m", "--msg"):
            msg = arg

    msg_bytes = hash_sha256(msg.encode())
    msg_hex = msg_bytes.hex()
    sig_bytes = bytes.fromhex(sig)
    pubkey_bytes = bytes.fromhex(pubkey)

    print('pubkey is:', pubkey)
    print('message digest is:', msg_hex)
    aux_rand_hex = "0000000000000000000000000000000000000000000000000000000000000001"
    aux_rand = bytes.fromhex(aux_rand_hex)
    print("The signature is: ", sig)
    print("The public key is: ", pubkey)
    print("Is the signature for this message and this public key?")
    print(schnorr_verify(msg_bytes, pubkey_bytes, sig_bytes))

if __name__ == "__main__":
   main(sys.argv[1:])


