import schnorr_lib as sl
import sys, json

def main(argv):

    # Get message and its digest
    msg = "messaggio da firmare"
    M = sl.sha256(msg.encode())

    # Get keypairs
    keypairs = json.load(open("keypairs.json", "r"))

    Rsum, ssum = sl.schnorr_musig_sign(M, keypairs)
    print(Rsum)
    print(ssum)
    
    # L = h(P1 || ... || Pn)
    # Li = b''
    # for u in keypairs["keypairs"]:
    #     Li += sl.pubkey_gen_from_hex(u["privateKey"])
    # L = sl.sha256(Li)

    # Psum = None
    # Rsum = None
    # X = None
    # for u in keypairs["keypairs"]:
    #     # Get private key di and public key Pi
    #     di = sl.bytes_from_hex(u["privateKey"])
    #     Pi = sl.pubkey_point_gen_from_int(sl.int_from_bytes(di))
    #     # Psum = P1 + ... + Pn
    #     if Psum == None:
    #         Psum = Pi
    #     else:
    #         Psum = sl.point_add(Psum, Pi)
        
    #     # Random ki with tagged hash
    #     t = sl.xor_bytes(di, sl.tagged_hash("BIP340/aux", sl.get_aux_rand()))
    #     ki = sl.int_from_bytes(sl.tagged_hash("BIP340/nonce", t + sl.bytes_from_point(Pi) + M)) % sl.n
    #     if ki == 0:
    #         raise RuntimeError('Failure. This happens only with negligible probability.')
    #     u["ki"] = ki

    #     # Ri = ki * G
    #     Ri = sl.point_mul(sl.G, ki)
    #     # Rsum = R1 + ... + Rn
    #     if Rsum == None:
    #         Rsum = Ri
    #     else:
    #         Rsum = sl.point_add(Rsum, Ri)

    #     # bi = h(L||Pi)
    #     bi = sl.int_from_bytes(sl.sha256(L + sl.bytes_from_point(Pi)))
    #     u["bi"] = bi

    #     # Xi = bi * Pi
    #     Xi = sl.point_mul(Pi, bi)
    #     # X = X1 + ... + Xn
    #     if X == None:
    #         X = Xi
    #     else:
    #         X = sl.point_add(X, Xi)

    # # e_ = h(X || Rsum || M)
    # e_ = sl.int_from_bytes(sl.sha256(sl.bytes_from_point(X) + sl.bytes_from_point(Rsum) + M))
    
    # ssum = 0
    # for u in keypairs["keypairs"]:
    #     # Get private key di
    #     di = sl.int_from_bytes(sl.bytes_from_hex(u["privateKey"]))
    #     # ei = h(X || Rsum || M) * bi
    #     ei = e_ * u["bi"]
    #     # si = ki + di * ei mod n
    #     si = (u["ki"] + (di * ei)) % sl.n
    #     # ssum = s1 + ... + sn
    #     ssum += si
    # ssum = ssum % sl.n
    
    # print(">>> The sig is (Rsum,ssum)")

    # # VERIFICATION
    # # ssum * G = Rsum + e_ * X
    # Rv = sl.point_mul(sl.G, ssum)
    # other = sl.point_mul(X, e_)
    # sumv = sl.point_add(Rsum, other)

    # print(">>> Is the sig right? (Rv equals Rsum + e'*X)?", Rv == sumv)

if __name__ == "__main__":
   main(sys.argv[1:])

