import json
import os
from Function.function import generate_key_pair, AES_KeyGen, SKE_E, AES_Enc, Enc, Elgamal_Enc, Hash_KeyGen, \
    Elgamal_sign
from Sign.Sign import sign
import secrets

# input VPK = (vpk_1,...vpk_n)
# input msg to be sent
# input secret key vsk_s
def Broadcast_Enc(VPK,input_msg,vsk_s,pp):
    # parse pp
    p = pp['p']
    g = pp['g']
    module = pp['G']['module']
    security_lambda = pp['security_lambda']
    # parse VPK
    n = len(VPK) # by anylyzing VPK, we can get the number of users
    epk = [];spk=[]
    for i in range(n):
        epk.append(VPK[i]['epk'])
        spk.append(VPK[i]['spk'])
    # parse vsk_s
    epk_s = vsk_s['epk']
    # esk_s = vsk_s['esk']
    ssk_s = vsk_s['ssk']
    # parse ssk_s
    pk_s = ssk_s['pk']
    y_s = ssk_s['y']
    # sk_s = ssk_s['sk']
    # x_s = ssk_s['x']
    # generate temporary Elgamal key pair
    tspk,tssk = generate_key_pair(security_lambda,pp['G'])
    # generate m1
    m1 = {"epk":epk,"input_msg":input_msg,"tspk":tspk};m1 = json.dumps(m1)
    # generate the m1 signature sigma
    sigma = sign(vsk_s=ssk_s,VPK=spk,pp=pp,n=n,msg=m1)
    # sample r and compute R
    r = secrets.randbelow(p);R = pow(g,r,module)
    # generate an AES key , type of k_sym is string
    k_sym = AES_KeyGen(security_lambda)
    # compute EPK_set and encrypt k_sym
    ct_set = [];r_set = [None] * n
    for j in range(n):
        # generate a AES key
        key = Hash_KeyGen(pow(epk[j],r,module),security_lambda)
        # construct the msg to be encrypted
        msg = {"k_sym":k_sym,"key":key};msg = json.dumps(msg);msg = msg.encode("utf-8")
        # generate r
        r_set[j] = os.urandom(12)
        # enc the msg
        ct_set.append(AES_Enc(msg,key,r_set[j]))
        r_set[j] = r_set[j].hex()
    # generate m2
    # the type of msg is bytes, we need turn it to str
    m2 = (epk_s,pk_s,y_s,spk,input_msg,sigma)
    # Encrypt (m2,r,VPK,r_set)
    ct_sym = SKE_E(k_sym,m2,r,VPK,r_set)
    # compute Signature (R,ct_sym,EPK_set,ct_set)
        # construct msg to be signed
    msg={"R":R,"ct_sym":ct_sym,"ct_set":ct_set}
    msg = json.dumps(msg)
    sigma_coma = Elgamal_sign(tssk,msg)
    # construct output ct_BC
    # tspk --> dict
    # R --> int
    # ct_sym -> dict(str,str,str)
    # ct_set -> element type == str, to use have to turn to bytes
    # sigma_coma -> (int,int)
    ct_BC = (tspk,R,ct_sym,ct_set,sigma_coma)
    return ct_BC
