import argparse

from schnorr_lib import schnorr_verify, sha256


def main():
    parser = argparse.ArgumentParser(
        description='Returns True or False from a public key, a message and a signature')
    parser.add_argument('-s', '--signature', type=str, required=True, help='signature')
    parser.add_argument("-p", "--public_key", type=str, required=True, help='Public key or public aggregate aggregate')
    parser.add_argument('-m', '--message', type=str, required=True, help='Message')
    
    args = parser.parse_args()
    pubkey = args.public_key
    msg = args.message
    sig = args.signature

    msg_bytes = sha256(msg.encode())
    sig_bytes = bytes.fromhex(sig)
    pubkey_bytes = bytes.fromhex(pubkey)

    print("The signature is: ", sig)
    print("The public key is: ", pubkey)
    print('The message digest is:', msg_bytes.hex())
    print("Is the signature for this message and this public key?")
    print(schnorr_verify(msg_bytes, pubkey_bytes, sig_bytes))

if __name__ == "__main__":
   main()
 

