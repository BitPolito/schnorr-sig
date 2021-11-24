import argparse, sys
from utils import print_fails, print_success
from schnorr_lib import schnorr_verify, sha256


def main():
    parser = argparse.ArgumentParser(
        description='It checks the validity of the sign and returns True or False from a public key, a message and a signature')
    parser.add_argument('-s', '--signature', type=str, required=True, help='signature')
    parser.add_argument("-p", "--public_key", type=str, required=True, help='Public key or public aggregate X~')
    parser.add_argument('-m', '--message', type=str, required=True, help='Message')
    
    args = parser.parse_args()
    pubkey = args.public_key
    msg = args.message
    sig = args.signature
    
    try: 
        msg_bytes = sha256(msg.encode())
        sig_bytes = bytes.fromhex(sig)
        pubkey_bytes = bytes.fromhex(pubkey)

        result = schnorr_verify(msg_bytes, pubkey_bytes, sig_bytes)
        print("\nThe signature is: ", sig)
        print("The public key is: ", pubkey)
        print('The message digest is:', msg_bytes.hex())
        print("\nIs the signature valid for this message and this public key? ")
        if result:
            print_success("Yes")
        else:
            print_fails("No")
    except Exception as e:
        print_fails("[e] Exception:", e)
        sys.exit(2)

if __name__ == "__main__":
   main()
 

