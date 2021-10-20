import schnorr_lib as sl
import sys, getopt, json
from binascii import hexlify, unhexlify 

# TODO controllare i tipi

def main(argv):

    msg = "messaggio da firmare"
    # msg_bytes = sl.hash_sha256(msg.encode()) # va effettuato l'hash? 
    msg_bytes = msg.encode()

    # Get keypairs
    keypairs = json.load(open("keypairs.json", "r"))
    
    l = ""
    for x in keypairs["keypairs"]:
        l += x["publicKey"] # concatenazione chiavi in hex
    L = sl.hash_sha256(unhexlify(l))

    Psum = (0, 0)
    Rsum = (0, 0)
    X = (0, 0)

    for i,x in enumerate(keypairs["keypairs"]):
        di = x["privateKey"]
        Pi = sl.pubkey_gen_from_hex(di)
        Psum = sl.point_add(Psum, Pi)
        
        # va bene generare k così? 
        t = sl.xor_bytes(unhexlify(di), sl.tagged_hash("BIP340/aux", sl.get_aux_rand()))
        ki = sl.int_from_bytes(sl.tagged_hash("BIP340/nonce", t + sl.bytes_from_point(Pi) + msg_bytes)) % sl.n
        if ki == 0:
            raise RuntimeError('Failure. This happens only with negligible probability.')
       
        keypairs["keypairs"][i]["ki"] = ki
        # print( keypairs["keypairs"][i]["ki"] = ki )

        Ri = sl.point_mul(sl.G, ki)
        Rsum = sl.point_add(Rsum, Ri)

        # bi = h(L||Pi), dove L = h(P1||..||Pn)
        bi = sl.hash_sha256(L+Pi)
        keypairs["keypairs"][i]["bi"] = bi
        # print( keypairs["keypairs"][i]["bi"] = bi )

        xi = sl.point_mul(Pi, sl.int_from_bytes(bi))
        X = sl.point_add(X, xi)

    e_ = sl.int_from_bytes(sl.hash_sha256(sl.bytes_from_point(X) + sl.bytes_from_point(Rsum) + msg_bytes))
    
    ssum = 0
    for x in keypairs["keypairs"]:
        # TODO dovremmo tornare in interi
        di = sl.int_from_bytes(unhexlify(x["privateKey"]))
        bi = sl.int_from_bytes(x["bi"])
        e = e_* bi % sl.n
        si = x["ki"]+di+e
        ssum += si % sl.n
    
    ssum = ssum % sl.n
    
    print(">>> Then the sign is (Rsum,ssum)")

    # TODO VERIFICATION

    # Rv = schnorr_lib.point_mul(ssum,schnorr_lib.G)
    # other = schnorr_lib.point_mul(e_,X)
    # sum = schnorr_lib.point_add(other,Rsum)

    # print("Rv = ssum*G =",Rv)
    # print("Rsum + e'*X =", Rsum, "+", other, "=", sum)
    # print(">>> The sign is right? (Rv equals Rsum + e'*X)?", Rv == sum)

if __name__ == "__main__":
   main(sys.argv[1:])

