from sympy import nextprime,isprime,primitive_root
from random import getrandbits, random
from math import gcd
from Function.function import generate_key_pair

# the Setup section
# secrurity_lambda is a security paeameter

def generate_prime_p(secrurity_lambda):
    #generate prime p,and ||p|| = secrurity_lambda

    random_number = getrandbits(secrurity_lambda)
    prime_p = nextprime(random_number)

    #make sure p only has secrurity_lambda bits length
    while prime_p.bit_length() != secrurity_lambda:
        random_number = getrandbits(secrurity_lambda)
        prime_p = nextprime(random_number)

    return prime_p

def module_caculate(prime_p):
    #caculate the mod
    n = 2
    while not isprime(n * prime_p+1):
        n = n+1
    return n

def another_generator(generator,module):
    order = module - 1
    k = 3
    while gcd(k,order) !=1:
        k+=1
    new_generator = pow(generator,k,module)
    return new_generator

# generate a cycle group G with prime order p
def generate_cycle_group(prime_p):
    n = module_caculate(prime_p)
    # caculate the module
    module = n*prime_p+1
    generator_np = primitive_root(module)
    generator_ap = another_generator(generator_np,module)
    # caculate the first generator g
    generator_g = pow(generator_np,n,module)
    # caculate the second generator h
    generator_h = pow(generator_ap,n,module)
    return generator_g,generator_h,module

def Setup(alpha,secrurity_lambda):
    # alpha is the error parameter
    # pp <- (secrurity_lambda,p,G,g,h,ppk,alpha)
    prime_p = generate_prime_p(secrurity_lambda)
    (g,h,module) = generate_cycle_group(prime_p)
    G = {"generator":g,
         "module":module}
    (ppk,psk) = generate_key_pair(secrurity_lambda,G)
    pp = {
        'security_lambda': secrurity_lambda,
        'p': prime_p,
        'G': {"generator":g,"module":module},
        'g': g,
        'h': h,
        'ppk': ppk,
        'alpha': alpha
    }
    return pp
