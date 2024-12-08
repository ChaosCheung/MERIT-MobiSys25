import math
import random
import secrets


from sympy import mod_inverse
from Function.function import HASH,phi,Sch_p,Enc,pk_exponentiation,caculate_inverse



# input vsk_s
# VPK=(vpk0,...,vpkn-1) and n
# pp

def generate_beta(alpha,rho,n):
    log_n = math.log(n,2) # base is 2
    log_rho = math.log(rho,2)
    molecule = alpha + log_n - log_rho
    log_n_np = math.log(n - n*rho,2)
    denominator = log_n_np - (log_rho/(1-rho))
    result = molecule / denominator
    beta = math.ceil(result)
    return beta

# output beta rho gamma
def sign_setup(alpha,n):
    # we assign rho = 0.8
    rho = 0.8
    beta = generate_beta(alpha,rho,n)
    gamma = n * beta / rho
    # to make sure that the gamma is an integer
    gamma = math.ceil(gamma)
    return beta,rho,gamma

# n can be computed as n = len(VPK)
# we can not take n as an input
def sign(vsk_s,VPK,pp,n,msg):
    # Pares pp
    alpha = pp['alpha']
    ppk = pp['ppk']
    g = pp['g']
    h = pp['h']
    p = pp['p']
    module = pp['G']['module']
    # parse vsk_s
    x_s = vsk_s['x']
    y_s = vsk_s['y']
    # setup
    (beta,rho,gamma) = sign_setup(alpha,n)
    S_0 = []
    S_1 = []
    u = [None] * gamma
    v = [None] * gamma
    u_coma = [None] * gamma
    v_coma = [None] * gamma
    Uset = [None] * gamma
    Vset = [None] * gamma
    ctpp_set = [None] * gamma
    r_pp = [None] * gamma
    pk = [None] * n # to store users' pks
    y = [None] * n # to store users' ys
    k = [None] * gamma # a random number set
    ct = [None] * gamma
    s = [None] * gamma
    t = [None] * gamma
    S_set = [None] * gamma
    T_set = [None] * gamma
    pi = [None] * gamma
    # caculate inverse_g
    inverse_g = mod_inverse(g, module)
    for i in range(gamma):
        u[i] = random.randint(0, p - 1)
        v[i] = random.randint(0, p - 1)
        u_coma[i] = random.randint(0, p - 1)
        v_coma[i] = random.randint(0, p - 1)
        r_pp[i] = random.randint(0, p - 1)
        Uset[i] = (pk_exponentiation(ppk, u_coma[i], module) * pow(inverse_g, u[i], module)) % module
        Vset[i] = (pk_exponentiation(ppk, v_coma[i], module) * pow(inverse_g, v[i], module)) % module
        ctpp_set[i] = Enc(ppk, msg, u[i], v[i], u_coma[i], v_coma[i], r_pp[i])
    # set b = 1 and b_set
    b = 1
    b_set = [None] * gamma
    # sample r
    r = secrets.randbelow(p)
    # generate pct
    pct_0 = pow(g,r,module)
    pct_1 = (pk_exponentiation(ppk,r,module) * pow(h,b,module)) % module
    pct = {
        "pct_0":pct_0,
        "pct_1":pct_1
    }
    # Use hash function to perform computation
    # Estring has gamma bits length
    Estring = HASH(pct,Uset,Vset,ctpp_set,gamma)
    for j in range(gamma) :
        if Estring[j] == '0':
            element_S0 = (j,u[j],v[j],u_coma[j],v_coma[j],r_pp[j])
            S_0.append(element_S0)
        else: # Estring[i] == 1
            i = phi(j,n,Estring)
            # set b_j = 1
            b_set[j] = 1
            #parse vpk[i]
            pk_i= VPK[i]['pk'];y_i=VPK[i]['y']
            # sample k_j
            k[j] = random.randint(0,p-1)
            # compute ct[j]
            ct[j] = (
                pow(g, k[j], module),
                (pk_exponentiation(pk_i, k[j], module) * pow(h, 1, module)) % module
            )
            # comput s[j] t[j]
            s[j] = u[j] + b_set[j]*x_s
            t[j] = v[j] + x_s
            # compute S_set[j]   T_set[j]
            S_set[j] = (pow(g,s[j],module) * Uset[j]) % module
            T_set[j] = (pow(g,t[j],module) * Vset[j]) % module
            # comput pi[j]
            pi[j] = Sch_p(b,r,b_set[j],k[j],u[j],v[j],u_coma[j],v_coma[j],x_s,ppk,g,module,pk_i,h,y_i,y_s,p,S_set[j])
            element_S1 = (j,s[j],t[j],ct[j],pi[j])
            S_1.append(element_S1)
    sigma ={
        "msg":msg,
        "pct":pct,
        "U":Uset,
        "V":Vset,
        "ctpp":ctpp_set,
        "S_0":S_0,
        "S_1":S_1
    }
    return sigma

