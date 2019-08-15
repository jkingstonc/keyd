import random
from . import utils


class keygen:

    @staticmethod
    def generate_private_key(max_size): # return a randomly generated private key
        return random.randint(0,max_size)

    @staticmethod
    def gen_key_public_key_(base, modulus, private_key_): # return a public key generated from a private key
        public_key_ = utils.exp_by_squaring(base,private_key_)%modulus
        return public_key_

    @staticmethod
    def gen_exchange_key_(public_key_, private_key_, modulus, pair_value): # return an exchange key generated from a public key and a private key
        return (utils.exp_by_squaring(public_key_,private_key_)%modulus)*pair_value

    @staticmethod
    def gen_key_64(key):
        return utils.gen_64_block(key, 1) # take a key as an integer, and return it as a 64 bit padded integer with 1's