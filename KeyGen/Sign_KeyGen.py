from Function.function import generate_key_pair
import secrets



# every user generates his/her personal key
# pp is the input
# (secrurity_lambda,p,G,h,ppk,alpha)
#output vpk vsk

def KeyGen(pp):
    security_lambda = pp['security_lambda']
    g = pp['g']
    module = pp['G']['module']
    p = pp['p']
    G = pp['G']
    (pk,sk) = generate_key_pair(security_lambda,G)
    x = secrets.randbelow(p)
    y = pow(g,x,module)
    return {
        "vpk":{"pk":pk,"y":y},
        "vsk":{"pk":pk,"y":y,"sk":sk,"x":x}
    }

