import json
import os
import secrets

from Function.function import generate_key_pair,Hash_KeyGen,AES_KeyGen,Elgamal_sign,AES_Enc,SKE_E
from Forge.Sign_forge import forge_sign

'''
input
pp -> public parameter
VKP -> a vector
VSK -> a vector
msg to be encrypted
'''

def forge_enc(pp,VPK,VSK,input_msg,vpk_s,):
    # parse pp
    g = pp['g'];module = pp['G']['module']
    security_lambda = pp['security_lambda']
    p = pp['p']
    # parse vpk_s
    epk_s = vpk_s['epk']
    pk_s = vpk_s['spk']['pk']
    y_s = vpk_s['spk']['y']
    # parse VPK
    n = len(VPK) # by anylyzing VPK, we can get the number of users
    epk = [];spk=[]
    for i in range(n):
        epk.append(VPK[i]['epk'])
        spk.append(VPK[i]['spk'])
    esk = [None] * n;ssk = [None] * n
    for j in range(n):
        if VSK[j] != None:
            esk[j] = VSK['esk']
            ssk[j] = VSK['ssk']
    # generate temporary Elgamal key pair
    tspk, tssk = generate_key_pair(pp['security_lambda'], pp['G'])
    # generate m1
    m1 = {"epk": epk, "input_msg": input_msg, "tspk": tspk};m1 = json.dumps(m1)
    # forge the signature sigma
    sigma = forge_sign(ssk,spk,pp,input_msg)
    # sample r and compute R
    r = secrets.randbelow(p);
    R = pow(g, r, module)
    # generate an AES key , type of k_sym is string
    k_sym = AES_KeyGen(security_lambda)
    # compute EPK_set and encrypt k_sym
    ct_set = [];
    r_set = [None] * n
    for j in range(n):
        # generate a AES key
        key = Hash_KeyGen(pow(epk[j], r, module),security_lambda)
        # construct the msg to be encrypted
        msg = {"k_sym": k_sym, "key": key};
        msg = json.dumps(msg);
        msg = msg.encode("utf-8")
        # generate r
        r_set[j] = os.urandom(12)
        # enc the msg
        ct_set.append(AES_Enc(msg, key, r_set[j]))
        r_set[j] = r_set[j].hex()
    # generate m2
    # the type of msg is bytes, we need turn it to str
    m2 = (epk_s, pk_s, y_s, spk, input_msg, sigma)
    # Encrypt (m2,r,VPK,r_set)
    ct_sym = SKE_E(k_sym, m2, r, VPK, r_set)
    # compute Signature (R,ct_sym,EPK_set,ct_set)
    # construct msg to be signed
    msg = {"R": R, "ct_sym": ct_sym, "ct_set": ct_set}
    msg = json.dumps(msg)
    sigma_coma = Elgamal_sign(tssk, msg)
    # construct output ct_BC
    # tspk --> dict
    # R --> int
    # ct_sym -> dict(str,str,str)
    # ct_set -> element type == str, to use have to turn to bytes
    # sigma_coma -> (int,int)
    ct_BC = (tspk, R, ct_sym, ct_set, sigma_coma)
    return ct_BC


