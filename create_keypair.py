from schnorr_lib import n, pubkey_gen_from_int, hash_sha256
import os


if __name__ == "__main__":
    
    priv = os.random(32)
    privkey = (int(priv, 16) % n)

    print("Your private key as integer is:", privkey)
    print()
    print("Your public key as hex is:", pubkey_gen_from_int(privkey).hex())
