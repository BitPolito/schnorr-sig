from schnorr_lib import n, pubkey_gen_from_int
import os, json, getopt, sys

def main(argv):

    try:
        opts, args = getopt.getopt(argv, "hn:", ["help", "nkeys="])
    except getopt.GetoptError:
        print('[i] Command not found. Type -h for help')
        sys.exit(2)
        
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print('[i] Command: create_keypair.py -n <number_of_keys>')
            sys.exit()
        elif opt in ("-n", "--nkeys"):
            if arg.isnumeric():
                n_keys = int(arg)
            else:
                print('[i] Number needed. Type -h for help ')
                sys.exit(2)
    
    if not opts:
        print('[i] Argument needed. Type -h for help ')
        sys.exit(2)

    # Create json
    keypairs = {
        "$schema": "./keypairs_schema.json",
        "keypairs": []
    }

    # Generate n keys
    for i in range(0, n_keys):
        priv = os.urandom(32)
        privkey = int(priv.hex(), 16) % n

        keypairs["keypairs"].append({
            "privateKey": hex(privkey).replace('0x', ''),
            "publicKey": pubkey_gen_from_int(privkey).hex()
        })

    json_object = json.dumps(keypairs, indent=4)
    with open("keypairs.json", "w") as f:
        f.write(json_object)
    
    print("[i] Keypair(s) generated:", n_keys)
    

if __name__ == "__main__":
    main(sys.argv[1:])

    
