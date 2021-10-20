import schnorr_lib as sl
import sys, getopt, json
from binascii import hexlify, unhexlify 

def main(argv):

    msg = "messaggio da firmare"
    # msg_bytes = sl.hash_sha256(msg.encode()) # va effettuato l'hash? 
    msg_bytes = msg.encode()

    O = sl.point_add(sl.G, sl.H)
    print(O)

    # Get keypairs
    keypairs = json.load(open("keypairs.json", "r"))
    
    l = b''
    for x in keypairs["keypairs"]:
        l += sl.pubkey_gen_from_hex(x["privateKey"])
    L = sl.hash_sha256(l)

    Psum = (0, 0)
    Rsum = (0, 0)
    X = (0, 0)
    for x in keypairs["keypairs"]:
        di = x["privateKey"]
        Pi = sl.pubkey_gen_from_hex(di)
        Psum = sl.point_add(Psum, Pi)
        
        # va bene generare k così? 
        t = sl.xor_bytes(unhexlify(di), sl.tagged_hash("BIP340/aux", sl.get_aux_rand()))
        ki = sl.int_from_bytes(sl.tagged_hash("BIP340/nonce", t + sl.bytes_from_point(Pi) + msg.encode())) % sl.n
        if ki == 0:
            raise RuntimeError('Failure. This happens only with negligible probability.')
        x["ki"] = ki

        Ri = sl.point_mul(sl.G, ki)
        Rsum = sl.point_add(Rsum, Ri)

        # bi = h(L||Pi), dove L = h(P1||..||Pn)
        bi = sl.int_from_bytes(sl.hash_sha256(L + Pi))
        x["bi"] = bi

        xi = sl.point_mul(Pi, sl.int_from_bytes(bi))
        X = sl.point_add(X, xi)

    e_ = sl.hash_sha256(sl.bytes_from_point(X) + sl.bytes_from_point(Rsum) + msg.encode())
    
    ssum = 0
    for x in keypairs["keypairs"]:
        di = sl.int_from_bytes(unhexlify(x["privateKey"]))
        ei = sl.int_from_bytes(e_) * x["bi"]
        si = x["ki"] + di + ei % sl.n
        ssum += si
    
    ssum = ssum % sl.n
    
    print(">>> Then the sign is (Rsum,ssum)")

    # VERIFICATION

    Rv = sl.point_mul(sl.G, ssum)
    other = sl.point_mul(X, sl.int_from_bytes(e_))
    sumv = sl.point_add(Rsum, other)

    # print("Rv = ssum*G =",Rv)
    # print("Rsum + e'*X =", Rsum, "+", other, "=", sum)
    print(">>> Is the sign right? (Rv equals Rsum + e'*X)?", Rv == sumv)

if __name__ == "__main__":
   main(sys.argv[1:])

