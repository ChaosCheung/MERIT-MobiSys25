import json
from Verify.Vrfy import Vrfy
from Function.function import Elgamal_verify, Hash_KeyGen, AES_Dec, SKE_D, AES_Enc



def Decrypt(ct_set,k):
    for element in ct_set:
        msg = AES_Dec(element,k)
        if msg != False: # if msg is not false
            k_sym = msg['k_sym']
            key = msg['key']
            if key == k:
                return k_sym
    return False

# input ct_BC, secret key vsk
def Broadcast_Dec(ct_BC,vsk,pp,sender_index,vrf_i):
    # parse pp
    module = pp['G']['module']
    g = pp['g']
    security_lambda = pp['security_lambda']
    # parse ct_BC
    tspk = ct_BC[0]
    R = ct_BC[1]
    ct_sym = ct_BC[2]
    ct_set = ct_BC[3]
    sigma_coma = ct_BC[4]
    # verify sigma_coma signature
        # construct msg
    msg = {"R": R, "ct_sym": ct_sym, "ct_set": ct_set}
    msg = json.dumps(msg)
        # verify signature
    result = Elgamal_verify(msg,sigma_coma,tspk)
    if result == False:
        return result # abort the DEC
    # parse vsk and ssk
    epk = vsk['epk'];esk = vsk['esk'];ssk = vsk['ssk']
    pk = ssk['pk'];y = ssk['y'];sk = ssk['sk'];x = ssk['x']
    # generate the user's AES key, and compute k_sym
    k = Hash_KeyGen(pow(R,esk,module),security_lambda)
    k_sym = Decrypt(ct_set,k)
    if k_sym == False:
        return k_sym # abort the DEC
    # Dec ct_sym and parse the result
    m2,r,VPK,r_set = SKE_D(ct_sym,k_sym)
    if R != pow(g,r,module):
        return False # if R != g**r,  abort
    # parse m2
    epk_s, pk_s, y_s, spk, input_msg, sigma = m2
    # parse VPK
    n = len(VPK)  # by anylyzing VPK, we can get the number of users
    epk = [];spk = []
    for i in range(n):
        epk.append(VPK[i]['epk'])
        spk.append(VPK[i]['spk'])
    # construct m1
    m1 = {"epk": epk, "input_msg": input_msg, "tspk": tspk};m1 = json.dumps(m1)
    # verify m1
    if m1 != sigma['msg']:
        return False
    # vrf the sigma
    # The last two parameters are implicit inputs
    VrfResult = Vrfy(pp,ssk,sigma,n,spk,sender_index,vrf_i)
    if VrfResult == False:
        return False
    for j in range(n):
        # compute ki
        ki = Hash_KeyGen(pow(epk[j],r,module))
        r_set[j] = bytes.fromhex(r_set[j])
        msg = {"k_sym": k_sym, "key": ki};msg = json.dumps(msg);msg = msg.encode("utf-8")
        if ct_set[j] != AES_Enc(msg,ki,r_set[j]):
            return False
    return input_msg,VPK

'''
with open("../pp.json","r") as file:
    pp = json.load(file)
with open("../Forge/enc.json","r") as file:
    enc  = json.load(file)
with open("../Broadcast_User/user3.json","r")as file:
    key = json.load(file)
    vsk_s = key['vsk']
msg= Broadcast_Dec(enc,vsk_s,pp)
print(msg)
'''