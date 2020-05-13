# a short straightforward intro on how to handle hex numbers
# https://appdividend.com/2019/10/28/python-hex-example-python-hex-function-psl/
#
# easy examples with ecdsa in python
# https://www.programcreek.com/python/example/81785/ecdsa.SECP256k1

import ecdsa
import base64

#
# parameters definition
#

#field_size
p=ecdsa.SECP256k1.curve.p()
#p_hex="0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
# p_hex == hex(p)

#curve order
n=ecdsa.curves.SECP256k1.generator.order()
#n=_hex"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
# n_hex == hex(n)

# generator point
xG=ecdsa.curves.SECP256k1.generator.x()
yG=ecdsa.curves.SECP256k1.generator.y()
#xG_hex="0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#yG_hex="0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
# xG_hex == hex(xG)
# yG_hex == hex(yG)
G=[xG,yG]
#
# function definition
#
def Int(x):
    return int(x,16)

def generate_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    private_key = sk.to_string().hex() #convert your private key to hex
    vk = sk.get_verifying_key() #this is your verification key (public key)
    public_key = vk.to_string().hex()
    #encode key to make it shorter
    public_key = base64.b64encode(bytes.fromhex(public_key))
    return [sk, vk, private_key, public_key]

def is_on_curve(P,mod=p):
    x=P[0]
    y=P[1]
    xval=(Int(x)**3+7) % Int(mod)
    yval=(Int(y)**2) % Int(mod)
    return xval == yval

def inv_point(P):
    y=hex(-Int(P[1]))
    return [P[0],y]

def point_sum(P,Q):
# TODO: how to treat float numbers? is it normal to have them?
    if (not is_on_curve(P)):
        return "first point is not on curve"
    if (not is_on_curve(Q)):
        return "second point is not on curve"
    # see 
    # https://en.wikipedia.org/wiki/Elliptic_curve#The_group_law
    xP=Int(P[0]); yP=Int(P[1])
    xQ=Int(Q[0]); yQ=Int(Q[1])
    if (xP != xQ):
        s=(yP-yQ)/(xP-xQ)
        xR=s**2-xP-xQ
        yR=yP+s(xR-xP)
        return [hex(xR),hex(yR)]
    else:
        if (yP == -yQ):
            return 0
        if (yP == yQ and yP != 0):
            s=(3*(xP**2))/(2*yP)
            xR = s**2-xP
            yR = yP+s*(xR-xP)
            return [hex(xR),hex(yR)]

    
#def is_infinite(P):
#    # returns whether or not P is the point at infinity
#
#def x_coord(P):
#    if (not is_infinite(P)):
#        return P[0]
#
#def y_coord(P):
#    if (not is_infinite(P)):
#        return P[1]


[sk,vk, priv_key, pub_key]=generate_keys()
print("the private key is:", priv_key)
print("the public key is:", pub_key)

print(sk)
