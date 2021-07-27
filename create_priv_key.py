from schnorrlib import n, pubkey_gen_from_int, hash_sha256

if __name__ == "__main__":
    string = str(input('Insert sentence as seed:\n'))

    dgst = hash_sha256(string.encode())
    dgst_hex = dgst.hex()
    privkey = (int(dgst_hex, 16) % n)

    print("Your seed phrase was:", string)
    print()
    print("Your private key as bytes is:", dgst)
    print("Your private key as hex is:", dgst_hex)
    print("Your private key as integer is:", privkey)
    print()
    print("Your public key as hex is:", pubkey_gen_from_int(privkey).hex())
