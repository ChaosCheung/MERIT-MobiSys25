import secrets
from KeyGen.Sign_KeyGen import KeyGen

# Broadcast setup steps are the same as the sign setup steps

# every user generates his/her personal key
# pp is the input
# (secrurity_lambda,p,G,h,ppk,alpha)
#output vpk vsk

def Broadcast_KeyGen(pp):
    p = pp['p']
    g = pp['g']
    module = pp['G']['module']
    KeyPair = KeyGen(pp)
    spk = KeyPair['vpk']
    ssk = KeyPair['vsk']
    esk = secrets.randbelow(p) # sample esk
    epk = pow(g,esk,module)
    return{
        "vpk":{"epk":epk,"spk":spk},
        "vsk":{"epk":epk,"esk":esk,"ssk":ssk}
    }



