from sympy import mod_inverse
from Function.function import HASH, phi, pk_exponentiation,caculate_inverse,Enc,Sch_V



# the index input is not that important, which can be computed in the code_block
def Vrfy(pp,vsk_new_i,sigma,n,VPK,sender_index,vrf_i):
# Setup Step
    # Parse pp
    security_lambda = pp['security_lambda']
    ppk = pp['ppk']
    g = pp['g']
    h = pp['h']
    module = pp['G']['module']

    # parse sigma
    Uset = sigma['U']
    Vset = sigma['V']
    ctpp_set = sigma['ctpp']
    S_0 = sigma['S_0']
    S_1 = sigma['S_1']
    pct = sigma['pct']
    msg = sigma['msg']
    gamma = len(Uset)

    # parse vsk
    sk = vsk_new_i['sk'][2]

    # set delta = 1
    delta = True

    # generate Sset and Tset
    Sset = [None] * gamma
    Tset = [None] * gamma

#start verification
    #compute Estring
    inverse_g = mod_inverse(g,module)
    Estring = HASH(gamma=gamma,pct=pct,U=Uset, V=Vset,ctpp=ctpp_set)
    S0_index = 0;S1_index = 0;
    for j in range(gamma):
        if Estring[j] == '0':
            element_S0 = ()
            # check wether element belongs to S_0
            if j in S_0[S0_index]:
                element_S0 = S_0[S0_index]
                S0_index = S0_index + 1
                delta = True
            else:
                delta = False
            if delta == False:
                break
            # get the elements
            u = element_S0[1];v=element_S0[2];u_coma=element_S0[3];v_coma=element_S0[4];r_pp=element_S0[5]
            # check whether the elemnts is right
            # first check Uset and Vset
            delta = delta and (Uset[j] == (pk_exponentiation(ppk,u_coma,module)* pow(inverse_g,u,module))% module
                               and
                               Vset[j] == (pk_exponentiation(ppk,v_coma,module)* pow(inverse_g,v,module))% module
                               )
            if delta == False:
                break
            # secondly check ctpp_set
            delta = delta and (ctpp_set[j] == Enc(ppk,msg,u,v,u_coma,v_coma,r_pp))
            if delta == False:
                break
        else: # Estring[j] == 1
            # compute i
            i = phi(j,n,Estring)

            # check j in S1
            element_S1 = ()
            if j in S_1[S1_index]:
                element_S1 = S_1[S1_index]
                S1_index = S1_index + 1
                delta = True
            else:
                delta = delta and False
            if delta == False:
                break
            # get the elements
            s = element_S1[1];t = element_S1[2];ct = element_S1[3];pi = element_S1[4]
            # compute Sset and Tset
            Sset[j] = (pow(g,s,module) * Uset[j]) % module
            Tset[j] = (pow(g,t,module) * Vset[j]) % module
            # Sch_V
            #delta = delta and (1 == Sch_V(Uset[j],Vset[j],ct,pct,Sset[j],Tset[j],VPK[i]['pk'],VPK[sender_index]['pk'],pi,module,g,h,ppk,VPK[i]['y'],VPK[sender_index]['y']))
            if delta == False:
                break
            if i == vrf_i:
                delta = delta and (
                    (ct[1] * caculate_inverse(ct[0],int(sk),module)) % module == h
                )
            if delta == False:
                break
    return delta

