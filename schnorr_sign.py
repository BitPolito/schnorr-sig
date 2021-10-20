from schnorr_lib import schnorr_sign, pubkey_gen_from_hex, sha256, get_aux_rand
import sys, getopt


def main(argv):
    seckey = ''
    msg = ''
    try:
        opts, args = getopt.getopt(argv, "hs:m:", ["sk=", "msg="])
    except getopt.GetoptError:
        # print('schnorr_sign.py -s <hex_secretkey> -m <message>')
        print('command not found')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('schnorr_sign.py -s <hex_secretkey> -m <message>')
            sys.exit()
        elif opt in ("-s", "--sk"):
            seckey = arg
        elif opt in ("-m", "--msg"):
            msg = arg

    msg_bytes = sha256(msg.encode())
    msg_hex = msg_bytes.hex()
    seckey_bytes = bytes.fromhex(seckey)
    aux_rand = get_aux_rand()
    sig = schnorr_sign(msg_bytes, seckey_bytes, aux_rand)
    print('The private key is:', seckey)
    print("The public key is: ", pubkey_gen_from_hex(seckey).hex())
    print('The message digest is:', msg_hex)
    print("The signature is: ", sig.hex())

if __name__ == "__main__":
   main(sys.argv[1:])

