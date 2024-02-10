from Crypto.Util import strxor
from itertools import islice, cycle

####
# Xor: take a bytearray + key as string in input and return a bytearray
####
def xor(data,key):
    key_int = map(ord, key)
    return strxor.strxor(data, bytearray(islice(cycle(key_int), len(data))))