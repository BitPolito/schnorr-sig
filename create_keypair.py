import argparse
import json
import os

from schnorr_lib import n, pubkey_gen_from_int


def main():
    parser = argparse.ArgumentParser(description='asks for a sentence (no newline characters), SHA256 hashes it and '
                                                 'then creates a key pair which can be used to schnorr_sign and '
                                                 'schnorr_verify a message')
    parser.add_argument('-n', '--nkeys', type=int, required=True, help='Number of pairs of keys to generate')
    n_keys = parser.parse_args().nkeys

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
    main()
