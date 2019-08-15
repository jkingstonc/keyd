from .encryptme import encryptme
from .keygen import keygen

DEFAULT_BASE = 512              # default base value used for keygen
DEFAULT_MODULUS = 1234567890    # default modulus value used for keygen
DEFAULT_EPOCH_SCALE=2           # default epoch scale for use by encryptme
DEFAULT_PAIR_VALUE=14051900     # default pair value for exchange key generation

class keyd_node:           # class representing a user using the encryption library

    def __init__(self, private_key=None, base=DEFAULT_BASE, modulus=DEFAULT_MODULUS, epoch_scale=DEFAULT_EPOCH_SCALE, pair_value=DEFAULT_PAIR_VALUE):

        self.base=base                  # base for use by key generation
        self.modulus=modulus            # modulus used for key generation
        self.epoch_scale=epoch_scale    # epoch scale used for encryption and decryption in encryptme

        self.pair_value=pair_value      # pair value used for exchange key generation

        self.private_key=private_key                                        # the user's private key
        if private_key == None: private_key= self.generate_private_key()    # if the user hasn't specified a private key, generate a random one
        self.public_key=self.generate_public_key()                          # generate a public key using keygen from the private key

        self.encryptme=encryptme(self.epoch_scale)  # initialise an incryptme object with the epoch scale

        self.exchange_key_dictionary = {} # initialise the exchange key dictionary; mapping public keys uniquely to exchange keys

    def generate_private_key(self): # generate a random private key
        self.private_key=keygen.generate_private_key(9999) # generate from the keygen library

    def generate_public_key(self): # generate a public key from the user's public key
        return keygen.gen_key_public_key_(self.base, self.modulus, self.private_key)

    def get_public_key(self):   # return the user's public key
        return self.public_key

    def init_exchange(self, other_public_key): # initialise an exchange with another person
        self.exchange_key_dictionary.update(   # add to the exchange key dictionary
            {other_public_key : keygen.gen_exchange_key_(other_public_key,self.private_key,self.modulus,self.pair_value)}  # generate an exchange key from the other public key
            )

    def close_exchange(self, other_public_key): # close an exchange with another user
        del self.exchange_key_dictionary[other_public_key] # delete an entry in the exchange key dictionary

    def encrypt(self,msg,other_public_key): # encrypt a message to sent to a user with specified public key
        if other_public_key in self.exchange_key_dictionary:
            return self.encryptme.keyd_encrypt(msg,self.exchange_key_dictionary[other_public_key]) # get exchange key from dictionary and encrypt

    def decrypt(self,msg,other_public_key): # decrypt a message sent from user with specified public key
        if other_public_key in self.exchange_key_dictionary:
            return self.encryptme.keyd_decrypt(msg,self.exchange_key_dictionary[other_public_key]) # get exchange key from dictionary and decrypt
