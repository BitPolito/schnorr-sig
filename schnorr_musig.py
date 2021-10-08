import schnorr_lib
import sys, getopt


def main(argv):
        
    # we start from here ...

    n = int(input("musig n-n, n: "))
    
    if ( n == 2):
        p1 = int(input("pK1 signer: "))
        p2 = int(input("pK2 signer: "))

        P1 = schnorr_lib.pubkey_gen(p1) 
        P2 = schnorr_lib.pubkey_gen(p2) 

        Psum = schnorr_lib.point_add(P1,P2)

        k1 = int(input("k1: "))
        k2 = int(input("k2: "))
        e_  = int(input("e' = h(Rsum||X||M): "))

        # bi = h(L||Pi), dove L = h(P1||..||Pn)
        b1 = int(input("b1: "))
        b2 = int(input("b2: "))

        x1 = schnorr_lib.point_mul(b1,P1)
        x2 = schnorr_lib.point_mul(b2,P2)

        X = schnorr_lib.point_add(x1,x2)

        R1 = schnorr_lib.point_mul(k1, schnorr_lib.G)
        R2 = schnorr_lib.point_mul(k2, schnorr_lib.G)

        Rsum = schnorr_lib.point_add(R1,R2)
        # e = e'*bi
        s1 = (k1+p1*e_*b1) % schnorr_lib.n
        s2 = (k2+p2*e_*b2) % schnorr_lib.n

        ssum = (s1+s2) % schnorr_lib.n

        print("x1 =", x1, "x2 =", x2, "X = x1 + x2 =", X)
        print("P1 =", P1, "P2 =", P2, "Psum = P1 + P2 =", Psum)
        print("R1 =", R1, "R2 =", R2, "Rsum = R1 + R2 =", Rsum)

        print("s1 = k + p1*e'*b1 mod N =",s1)
        print("s2 = k + p2*e'*b2 mod N =",s2)
        print("ssum = s1 + s2 mod N =",ssum)

        print(">>> Then the sign is (Rsum,ssum)")

        print("    verification")
    
        Rv = schnorr_lib.point_mul(ssum,schnorr_lib.G)
        other = schnorr_lib.point_mul(e_,X)
        sum = schnorr_lib.point_add(other,Rsum)

        print("Rv = ssum*G =",Rv)
        print("Rsum + e'*X =", Rsum, "+", other, "=", sum)
        print(">>> The sign is right? (Rv equals Rsum + e'*X)?", Rv == sum)

if __name__ == "__main__":
   main(sys.argv[1:])

