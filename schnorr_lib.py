from typing import Tuple, Optional
from binascii import unhexlify
import hashlib, os, json

# Elliptic curve parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# Points are tuples of X and Y coordinates
# the point at infinity is represented by the None keyword
Point = Tuple[int, int]

# Get bytes from an int
def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

# Get bytes from a hex
def bytes_from_hex(x: hex) -> bytes:
    return unhexlify(x)

# Get bytes from a point
def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P))

# Get an int from bytes
def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

# Get an int from hex
def int_from_hex(x: hex) -> int:
    return int.from_bytes(unhexlify(x), byteorder="big")

# Get x coordinate from a point
def x(P: Point) -> int:
    return P[0]

# Get y coordinate from a point
def y(P: Point) -> int:
    return P[1]

# Point addition
def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

# Point multiplication
def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

# Note: 
# This implementation can be sped up by storing the midstate
# after hashing tag_hash instead of rehashing it all the time
# Get the hash digest of (tag_hashed || tag_hashed || message)
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

# Check if a point is at infinity
def is_infinity(P: Optional[Point]) -> bool:
    return P is None

# Get xor of bytes
def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(x ^ y for (x, y) in zip(b0, b1))

# Get a point from bytes
def lift_x_square_y(b: bytes) -> Optional[Point]:
    x = int_from_bytes(b)
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y)

def lift_x_even_y(b: bytes) -> Optional[Point]:
    P = lift_x_square_y(b)
    if P is None:
        return None
    else:
        return (x(P), y(P) if y(P) % 2 == 0 else p - y(P))

# Get hash digest with SHA256
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

# Check if an int is square
def is_square(x: int) -> bool:
    return int(pow(x, (p - 1) // 2, p)) == 1

# Check if a point has square y coordinate
def has_square_y(P: Optional[Point]) -> bool:
    infinity = is_infinity(P)
    if infinity:
        return False
    assert P is not None
    return is_square(y(P))

# Check if a point has even y coordinate
def has_even_y(P: Point) -> bool:
    return y(P) % 2 == 0

# Generate public key from an int
def pubkey_gen_from_int(seckey: int) -> bytes:
    P = point_mul(G, seckey)
    assert P is not None
    return bytes_from_point(P)

# Generate public key from a hex
def pubkey_gen_from_hex(seckey: hex) -> bytes:
    seckey = bytes.fromhex(seckey)
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError(
            'The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P)

# Generate public key (as a point) from an int
def pubkey_point_gen_from_int(seckey: int):
    P = point_mul(G, seckey)
    assert P is not None 
    return P

# Generate auxiliary random of 32 bytes
def get_aux_rand() -> bytes:
    return os.urandom(32)

# Extract R_x int value from signature 
def get_int_R_from_sig(sig: bytes) -> int:
    return int_from_bytes(sig[0:32])

# Extract s int value from signature 
def get_int_s_from_sig(sig: bytes) -> int:
    return int_from_bytes(sig[32:64])

# Extract R_x bytes from signature 
def get_bytes_R_from_sig(sig: bytes) -> int:
    return sig[0:32]

# Extract s bytes from signature 
def get_bytes_s_from_sig(sig: bytes) -> int:
    return sig[32:64]

# Generate Schnorr signature
def schnorr_sign(msg: bytes, privateKey: str) -> bytes:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    d0 = int_from_hex(privateKey)
    if not (1 <= d0 <= n - 1):
        raise ValueError(
            'The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP340/aux", get_aux_rand()))
    k0 = int_from_bytes(tagged_hash(
        "BIP340/nonce", t + bytes_from_point(P) + msg)) % n
    if k0 == 0:
        raise RuntimeError(
            'Failure. This happens only with negligible probability.')
    R = point_mul(G, k0)
    assert R is not None
    k = n - k0 if not has_even_y(R) else k0
    e = int_from_bytes(tagged_hash("BIP340/challenge",
                                   bytes_from_point(P) + bytes_from_point(R) + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    
    if not schnorr_verify(msg, bytes_from_point(P), sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

# Verify Schnorr signature
def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = lift_x_even_y(pubkey)
    r = get_int_R_from_sig(sig)
    s = get_int_s_from_sig(sig)
    if (P is None) or (r >= p) or (s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIP340/challenge",
                                   pubkey + get_bytes_R_from_sig(sig) + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (not has_even_y(R)):
        # print("Please, recompute the sign. R is None or has even y")
        return False
    if (x(R) != r):
        # print("There's something wrong")
        return False
    return True

# Generate Schnorr MuSig signature
def schnorr_musig_sign(msg: bytes, users: list) -> bytes:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    
    # Key aggregation (KeyAgg), L = h(P1 || ... || Pn)
    L = b''
    for u in users:
        L += pubkey_gen_from_hex(u["privateKey"])
    L = sha256(L)

    Rsum = None
    X = None
    for u in users:
        # Get private key di and public key Pi
        di = int_from_hex(u["privateKey"])
        if not (1 <= di <= n - 1):
            raise ValueError('The secret key must be an integer in the range 1..n-1.')
        Pi = pubkey_point_gen_from_int(di)
        assert Pi is not None
        # FIXME: 
        # di = di if has_even_y(Pi) else n - di

        # KeyAggCoef
        # ai = h(L||Pi)
        ai = int_from_bytes(sha256(L + bytes_from_point(Pi)))
        u["ai"] = ai

        # Computation of X~
        # X~ = X1 + ... + Xn, Xi = ai * Pi 
        X = point_add(X, point_mul(Pi, ai))

        # Random ki with tagged hash
        t = xor_bytes(bytes_from_int(di), tagged_hash("BIP340/aux", get_aux_rand()))
        ki = int_from_bytes(tagged_hash(
            "BIP340/nonce", t + bytes_from_point(Pi) + msg)) % n
        if ki == 0:
            raise RuntimeError(
                'Failure. This happens only with negligible probability.')
        
        # Ri = ki * G
        Ri = point_mul(G, ki)
        assert Ri is not None
        
        # Rsum = R1 + ... + Rn
        Rsum = point_add(Rsum, Ri)       
        u["ki"] = ki

    # FIXME:
    # The aggregate public key X~ needs to be y-even
    if not has_even_y(X):
        for i,u in enumerate(users):
            users[i]["ai"] = n - u["ai"]

    # FIXME: 
    # If the aggregated nonce does not have an even Y
    # then negate  individual nonce scalars (and the aggregate nonce)
    if  not has_even_y(Rsum):
        for i,u in enumerate(users):
            users[i]["ki"] = n - u["ki"]

    # c = hash( X || Rsum || M )
    c = int_from_bytes(tagged_hash("BIP340/challenge",
        (bytes_from_point(X) + bytes_from_point(Rsum) + msg))) % n

    ssum = 0
    for u in users:
        # Get private key di
        di = int_from_hex(u["privateKey"])
        # FIXME: 
        # Pi = pubkey_point_gen_from_int(di)        
        # di = di if has_even_y(Pi) else n - di
        
        # ci = h(X || Rsum || M) * ai
        ci = c * u["ai"]
       
        # ssum = s1 + ... + sn,  # si = ki + di * ci mod n
        ssum += ((di * ci) + u["ki"]) % n
    ssum = ssum % n

    signature_bytes = bytes_from_point(Rsum) + bytes_from_int(ssum)

    # FIXME: 
    print("Musig verify: \033[92m", schnorr_verify(msg, bytes_from_point(X), signature_bytes),"\033[0m\n")
    if not schnorr_verify(msg, bytes_from_point(X), signature_bytes):
        raise RuntimeError('The created signature does not pass verification.')
    return signature_bytes, bytes_from_point(X)

# Generate Schnorr MuSig2 signature
def schnorr_musig2_sign(msg: bytes, users: list) -> bytes:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')

    nu = 2

    # Key aggregation (KeyAgg), L = h(P1 || ... || Pn)
    L = b''
    for u in users:
        L += pubkey_gen_from_hex(u["privateKey"])
    L = sha256(L)

    X = None
    for u in users:
        # Get private key di and public key Pi
        di = int_from_hex(u["privateKey"])
        if not (1 <= di <= n - 1):
            raise ValueError('The secret key must be an integer in the range 1..n-1.')
        Pi = pubkey_point_gen_from_int(di)
        assert Pi is not None
        # FIXME:        
        # di = di if has_even_y(Pi) else n - di

        # KeyAggCoef
        # ai = h(L||Pi)
        ai = int_from_bytes(sha256(L + bytes_from_point(Pi)))
        u["ai"] = ai

        # Computation of X~
        # X~ = X1 + ... + Xn, Xi = ai * Pi 
        X = point_add(X, point_mul(Pi, ai))

        # First signing round (Sign and SignAgg) 
        r_list = []
        R_list = []
        for j in range(nu):
            # Random r with tagged hash
            t = xor_bytes(bytes_from_int(di), tagged_hash("BIP340/aux", get_aux_rand()))
            r = int_from_bytes(tagged_hash(
                "BIP340/nonce", t + bytes_from_point(Pi) + msg)) % n
            if r == 0:
                raise RuntimeError(
                    'Failure. This happens only with negligible probability.')
        
            # Ri,j = ri,j * G (i rapresent the user)
            Rij = point_mul(G, r)
            assert Rij is not None

            r_list.append(r)
            R_list.append(Rij)            
        u["r_list"] = r_list
        u["R_list"] = R_list

    # SignAgg
    # for each j in {1 .. nu} aggregator compute Rj as sum of Rij  (where i goes
    # from 1 to n, and n is the number of user, while j is fixed for each round)
    # Rj is a set, where its size is nu
    Rj_list = []
    for j in range(nu):
        Rj_list.append(None)
        for u in users:
            Rj_list[j] = point_add(Rj_list[j], u["R_list"][j])
    
    # Second signing round (Sign', SignAgg', Sign'')
    # Sign'
    Rbytes = b''
    for Rj in Rj_list:
        Rbytes += bytes_from_point(Rj)

    # b = h(X || R1 || R2 || M)
    b = sha256(bytes_from_point(X) + Rbytes + msg)

    Rsum = None
    for j, Rj in enumerate(Rj_list):
        # Rsum = SUM (Rj * b^(j))  (Rsum is R in the paper) 
        Rsum = point_add(Rsum, point_mul(Rj, int_from_bytes(b) ** j))
    assert Rsum is not None   

    # FIXME:
    # The aggregate public key X~ needs to be y-even
    if not has_even_y(X):
        for i,u in enumerate(users):
            users[i]["ai"] = n - u["ai"]

    # FIXME: 
    # If the aggregated nonce does not have an even Y
    # then negate  individual nonce scalars (and the aggregate nonce)
    if  not has_even_y(Rsum):
        for i,u in enumerate(users):
            for j,r in enumerate(users[i]["r_list"]):
                users[i]["r_list"][j] = n - users[i]["r_list"][j]
    

    # c = hash( X || Rsum || M )
    c = int_from_bytes(tagged_hash("BIP340/challenge",
        (bytes_from_point(X) + bytes_from_point(Rsum) + msg))) %n

    # SignAgg' step
    ssum = 0
    for u in users:
        # Get private key di
        di = int_from_hex(u["privateKey"])
        # FIXME: 
        # Pi = pubkey_point_gen_from_int(di)        
        # di = di if has_even_y(Pi) else n - di

        rb = 0 
        for j in range(nu):
            rb += u["r_list"][j] * int_from_bytes(b)**j

        # ci = h(X || Rsum || M) * ai
        ci = c * u["ai"] 

        # ssum = s1 + ... + sn, si = (c*ai*di + r) % n
        ssum += (di * ci + rb) % n
    ssum = ssum % n

    signature_bytes = bytes_from_point(Rsum) + bytes_from_int(ssum)

    # FIXME: 
    print("Musig verify: \033[92m", schnorr_verify(msg, bytes_from_point(X), signature_bytes),'\033[0m\n')
    if not schnorr_verify(msg, bytes_from_point(X), signature_bytes):
        raise RuntimeError('The created signature does not pass verification.')
    return signature_bytes, bytes_from_point(X)
