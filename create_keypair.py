import argparse, json, os

from schnorr_lib import n, has_even_y, pubkey_point_gen_from_int, bytes_from_point 


def main():
    parser = argparse.ArgumentParser(description='Creates one or more key pairs which are stored in a JSON file and can be used to sign and verify a message')
    parser.add_argument('-n', '--nkeys', type=int, required=False, help='Number of pairs of keys to generate, if not specified a single keypair will be generated')
    n_keys = parser.parse_args().nkeys

    if not n_keys: 
        n_keys = 1

    # Create json
    users = {
        "$schema": "./users_schema.json",
        "users": []
    }

    # Generate n keys
    for i in range(0, n_keys):
        priv = os.urandom(32)
        privkey = int(priv.hex(), 16) % n

        publickey = pubkey_point_gen_from_int(privkey)

        # if (not has_even_y(publickey)):
        #     privkey = n - privkey
        print("P["+str(i)+"] is even:", has_even_y(publickey))

        hex_privkey = hex(privkey).replace('0x', '').rjust(64, '0')
        users["users"].append({
            "privateKey": hex_privkey ,
            "publicKey": bytes_from_point(publickey).hex()
        })

    json_object = json.dumps(users, indent=4)
    with open("users.json", "w") as f:
        f.write(json_object)

    print("[i] Keypair(s) generated:", n_keys)


if __name__ == "__main__":
    main()
