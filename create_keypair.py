from schnorr_lib import n, pubkey_gen_from_int
import os


if __name__ == "__main__":
    
    priv = os.urandom(32)
    privkey = int(priv.hex(), 16) % n
    
    print("Your private key as hex is:", hex(privkey).replace('0x', ''))
    print()
    print("Your public key as hex is:", pubkey_gen_from_int(privkey).hex())
