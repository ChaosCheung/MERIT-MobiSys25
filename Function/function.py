import cryptography
from Crypto.Random import random
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from Crypto.Util.number import GCD
from sympy import mod_inverse
import json


# generate key pair in elgamal
def generate_key_pair(security_lambda,G):
    p = G['module'];g = G['generator']
    x = random.randint(0,p-1)
    y = pow(g,x,p)
    pk = (p,g,y);sk = (p,g,x,y)
    return pk,sk

def Elgamal_Enc(public_key, msg, r):
    p, g, y = public_key
    c1 = pow(g, r, p)
    c2 = (string_to_int(msg) * pow(y, r, p)) % p
    return [c1, c2]

# Elgamal 解密函数
def Elgamal_Dec(private_key, encrypt_msg):
    p, g, x, y = private_key
    c1, c2 = encrypt_msg
    s = pow(c1, x, p)
    s_inv = pow(s, p-2, p)
    m = (c2 * s_inv) % p
    return int_to_string(m)

# encrypt msg with random number
def Enc(ppk, msg, u_j, v_j, u_coma_j, v_coma_j, r_pp_j):
   combine_msg = f"{msg}{u_j}{v_j}{u_coma_j}{v_coma_j}"
   encrypt_msg = Elgamal_Enc(ppk,combine_msg,r_pp_j)
   return encrypt_msg


# caculate elgamal pk**x
# Elgamal pk has two elements: e and n
# we create a way
def pk_exponentiation(pk, x, module):
    pk_data = pk[2]
    result = pow(pk_data, x, module)
    return result

def string_to_int(input_string):
    bytes_representation = input_string.encode('utf-8')
    integer_representation = int.from_bytes(bytes_representation, 'big')
    return integer_representation


def int_to_string(input_integer):
    bytes_representation = input_integer.to_bytes((input_integer.bit_length() + 7) // 8, 'big')
    string_representation = bytes_representation.decode('utf-8')
    return string_representation

def HASH(pct, U, V, ctpp, gamma=168):
    # hash function -> SHA256
    # pct is a tuple, and U, V, ctpp are lists
    hasher = hashlib.sha256()
    data_to_hash = f"{pct}{U}{V}{ctpp}"
    hasher.update(data_to_hash.encode('utf-8'))
    hash_bytes = hasher.digest()
    hash_binary = ''.join(f'{byte:08b}' for byte in hash_bytes)
    # Adjust the hash to gamma bits: extend or truncate as needed
    if len(hash_binary) < gamma:
        repeat_factor = (gamma // len(hash_binary)) + 1
        hash_binary = (hash_binary * repeat_factor)[:gamma]
    else:
        hash_binary = hash_binary[:gamma]
    return hash_binary # Make sure to return the result

def generate_permutation(n, hash_string):
    permutation = list(range(n))
    hash_length = len(hash_string) // 8
    for i in range(len(permutation)-1, 0, -1):
        hash_segment = hash_string[(i % hash_length) * 8: ((i % hash_length) + 1) * 8]
        hash_seed = int(hash_segment, 2)
        j = hash_seed % (i + 1)
        permutation[i], permutation[j] = permutation[j], permutation[i]
    return permutation

def phi(j,n,hash_string):
    # phi is a function
    # input \in [0,gamma)
    # output \in [0,n)
    # curretrnly,function phi is simple
    permutation = generate_permutation(n,hash_string)
    return permutation[j%n]

def Sch_p(b, r, b_j, k_j, u_j, v_j, u_coma_j, v_coma_j, x_s,ppk, g, module, pk_i, h, y_i, y_s,p,S):
    # construct the element
    element = (b,r,b_j,k_j,u_j,v_j,u_coma_j,v_coma_j)
    r = [None] * 8;z_phi = [None] * 8;c_phi = random.randint(0,p-1)
    for i in range(8):
        r[i] = random.randint(0,p-1);z_phi[i] = random.randint(0,p-1)
    U_j =(pk_exponentiation(ppk,r[6],module) * caculate_inverse(g,r[4],module)) % module
    V_j =(pk_exponentiation(ppk,r[7],module) * caculate_inverse(g,r[5],module)) % module
    ct = (
        pow(g,r[3],module) , (pk_exponentiation(pk_i,r[3],module) * pow(h,r[2],module) % module)
    )
    pct = (
        pow(g,r[1],module) , (pk_exponentiation(ppk,r[1],module) * pow(h,r[0],module) % module)
    )
    T_j = (pow(y_i,r[0]+r[2],module) * pk_exponentiation(ppk,r[7],module)) % module
    S_j = (pow(y_s,r[2],module) * pk_exponentiation(ppk,r[6],module)) % module
    S_j_phi = (pow(y_i,z_phi[2],module) * pk_exponentiation(ppk,z_phi[6],module) * caculate_inverse(S,c_phi,module)) % module
    # stimulate the challenge e
    e = random.randint(0,p--1)
    # compute c
    c = e ^ c_phi;z = [None] * 8
    for i in range(8):
        z[i] = r[i] + c * element[i]
    return (U_j,V_j,ct,pct,T_j,S_j,S_j_phi,c,c_phi,z,z_phi[2],z_phi[6])


def Sch_V(U,V,ct,pct,S,T,vpk,vpk_s,pi,module,g,h,ppk,y_i,y_s):
    U_j, V_j, ct_phi, pct_phi, T_j, S_j, S_j_phi, c, c_phi, z, z_phi3, z_phi7 = pi
    cond1 = (
                    ((U_j * pow(U, c, module)) % module) ==
                    ((pk_exponentiation(ppk, z[6], module) * caculate_inverse(g, z[4], module)) % module)
            ) and (
                    ((V_j * pow(V, c, module)) % module) ==
                    ((pk_exponentiation(ppk, z[7], module) * caculate_inverse(g, z[5], module)) % module)
            )
    if not cond1:
        return 0
    cond2 = (
                    ((ct_phi[0] * pow(ct[0], c, module)) % module) ==
                    (pow(g, z[3], module))
            ) and (
                    ((ct_phi[1] * pow(ct[1], c, module)) % module) ==
                    ((pk_exponentiation(vpk, z[3], module) * pow(h, z[2], module)) % module)
            )
    if not cond2:
        return 0
    cond3 = (
                    ((pct_phi[0] * pow(pct['pct_0'], c, module)) % module) ==
                    (pow(g, z[1], module))
            ) and (
                    ((pct_phi[1] * pow(pct['pct_1'], c, module)) % module) ==
                    ((pk_exponentiation(ppk, z[1], module) * pow(h, z[0], module)) % module)
            )
    if not cond3:
        return 0
    cond4 = (
            ((T_j * pow(T, c, module)) % module) ==
            ((pow(y_i, z[0] + z[2], module) * pk_exponentiation(ppk, z[7], module)) % module)
    )
    if not cond4:
        return 0
    cond5 = (
            (
                    ((S_j * pow(S, c, module)) % module) ==
                    ((pow(y_s, z[2], module) * pk_exponentiation(ppk, z[6], module)) % module)
            ) and (
                    ((S_j_phi * pow(S, c_phi, module)) % module) ==
                    ((pow(y_i, z_phi3, module) * pk_exponentiation(ppk, z_phi7, module)) % module)
            )
    )
    if not cond5:
        return 0
    return 1

# caculate the inverse
def caculate_inverse(g,u,module):
    g_u = pow(g,u,module)
    inverse = mod_inverse(g_u,module)
    return inverse

def AES_KeyGen(security_lambda):
    valid_key_sizes = [128, 192, 256]
    closest_key_size = min(valid_key_sizes, key=lambda x: abs(x - (security_lambda / 8)))
    key = os.urandom(closest_key_size // 8)
    return key.hex()

def AES_Enc(msg,key,iv = None):
    key = bytes.fromhex(key)
    if iv == None:
        iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(msg) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return {
        "iv":iv.hex(),
        "tag":(encryptor.tag).hex(),
        "ciphertext":ciphertext.hex()
    }

def AES_Dec(encrtypt_msg,key):
    key = bytes.fromhex(key)
    iv = encrtypt_msg['iv'];tag = encrtypt_msg['tag'];ciphertext = encrtypt_msg['ciphertext']
    iv = bytes.fromhex(iv);tag = bytes.fromhex(tag);ciphertext = bytes.fromhex(ciphertext)
    try:
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        msg = unpadder.update(padded_data) + unpadder.finalize()
        msg = msg.decode('utf8')
        msg = json.loads(msg)
        return msg  # the type of msg is dict
    except cryptography.exceptions.InvalidTag:
        return False

def SKE_E(key,m,r,VPK,r_set):
    # type of key is string
    # construct msg and turn it to bytes type
    msg = {
        "m":m,
        "r":r,
        "VPK":VPK,
        "r_set":r_set
    }
    msg = json.dumps(msg)
    msg = msg.encode('utf-8')
    encrypt_msg = AES_Enc(msg,key)
    return encrypt_msg

def SKE_D(encrypt_msg,key):
    msg = AES_Dec(encrypt_msg,key)
    m = msg['m'];r = msg['r'];VPK = msg['VPK'];r_set = msg['r_set']
    return m,r,VPK,r_set



def Elgamal_sign(private_key,msg):
    hash_obj = hashlib.sha256(msg.encode())
    hash_value = int.from_bytes(hash_obj.digest(), byteorder='big')
    # parse private_key
    p = private_key[0]
    g = private_key[1]
    x = private_key[2]
    k = random.StrongRandom().randint(1, int(p) - 2)
    while GCD(k, int(p) - 1) != 1:
        k = random.StrongRandom().randint(1, int(p) - 2)
    # compute r = g^k mod p
    r = pow(int(g), k, int(p))
    # compute s = (hash_value - x * r) * k^-1 mod (p-1)
    k_inv = mod_inverse(k, int(p) - 1)  # 计算 k 的模逆
    s = (hash_value - int(x) * r) * k_inv % (int(p) - 1)
    # seturn sig (r, s)
    return (r, s)


def Elgamal_verify(msg, sig, public_key):
    hash_obj = hashlib.sha256(msg.encode())
    hash_value = int.from_bytes(hash_obj.digest(), byteorder='big')
    # parse pk
    p = public_key[0]
    g = public_key[1]
    y = public_key[2]
    # parse sig
    r, s = sig
    if not (0 < r < int(p)):
        return False
     # compute g^hash_value mod p
    left = pow(int(g), hash_value, int(p))
    # compute y^r * r^s mod p
    right = (pow(int(y), r, int(p)) * pow(r, s, int(p))) % int(p)
    return left == right

def Hash_KeyGen(input,security_lambda = 1024):
    # map the input to an AES key
    valid_key_sizes = [128, 192, 256]
    closest_key_size = min(valid_key_sizes, key=lambda x: abs(x - (security_lambda / 8)))
    hash_obj = hashlib.sha256(str(input).encode())
    aes_key = hash_obj.digest()[:int(closest_key_size / 8)]
    return aes_key.hex()

