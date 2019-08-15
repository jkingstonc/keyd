
from .keygen import keygen
from . import utils

EPOCH_GROWTH = 2 # exponential value for the epoch to be raised to the power of, if greater than 2, may not work

DEBUG=False

class encryptme: # main encryption class

    def __init__(self, epoch_scale):
        self.epoch_scale=epoch_scale # initialise the epoch scale

    
    # msg -> string, key -> int
    def keyd_encrypt(self,msg,key): # main entry point for encryption
        key_64=keygen.gen_key_64(key) # generate a 64 bit exchange key from the entered key
        epochs=int(str(key)[:self.epoch_scale]) # get number of epochs (first n digits of the exchange key where n is epoch scale)
        chunk_array=utils.gen_chunk_array(msg) # generate a chunk array from the message string
        encrypted_chunk_array = encryptme.chunk_array_encrypt(chunk_array,key_64,epochs) # encrypt the chunk array
        encrypted_message=utils.encrypted_chunks_to_string(encrypted_chunk_array) # generate an integer string from the encrypted chunk array
        
        if DEBUG:
            print("ENCRYPT -> input exchange key: "+str(key))
            print("ENCRYPT -> number of epochs: "+str(epochs))
            print("ENCRYPT -> chunk array: "+str(chunk_array))
            print("ENCRYPT -> encrypted chunk array: "+str(encrypted_chunk_array))

        return encrypted_message

    @staticmethod
    # chunk_array -> int[], key -> int, epoch -> int
    def chunk_array_encrypt(chunk_array, key_64, epochs): # encrypt a chunk array with a 64 bit key and an number of epochs
        encrypted_chunk_array=chunk_array # initialise encrypted chunk array to current chunk array (will be iteratively updated)
        new_key_64 = key_64               # initialise new key to current key (will be iteratively updated)

        for epoch in range(epochs):       # encrypt, 'epoch' number of times
            encrypted_chunk_array, new_key_64 = encryptme.epoch_encrypt(encrypted_chunk_array,new_key_64,epoch) # encrypt chunks using key and current epoch
        return encrypted_chunk_array # return the encrypted chunks

    @staticmethod
    # chunk_array -> int[], key -> int, epoch -> int
    def epoch_encrypt(chunk_array, key, epoch): # encrypt a chunk array at a specific epoch
        new_chunk_array=[]                                  # initialise new chunk array (each epoch generates a new chunk array)
        new_key=0                                           # initialise new key (each epoch generates a new key)

        for i in range(len(chunk_array)):                   # loop through each chunk
            new_chunk_array.append(chunk_array[i] ^ key)    # each chunk is xord with the key, until we reach the last chunk
            if i != 0:                                      # if we are not at the first chunk
                new_chunk_array[i]=new_chunk_array[i] ^ new_chunk_array[i-1] # xor the current chunk in the new array with the previous chunk in the new array
            if i == len(chunk_array)-1:                     # we have reached the last chunk
                epoch_key = utils.gen_64_block(epoch**EPOCH_GROWTH, 1) # generate a new epoch key using the epoch number squared, it pads the binary key with 1s
                new_key= key ^ epoch_key                    # generate a new key by xoring the current key with the epoch key
        return new_chunk_array, new_key                     # return the new chunk array and the new key


    # msg -> int, key -> int
    def keyd_decrypt(self,msg, key): # main entry point for decryption
        key_64=keygen.gen_key_64(key) # generate a 64 bit exchange key from the entered key
        epochs=int(str(key)[:self.epoch_scale]) # get number of epochs (first n digits of the exchange key where n is epoch scale)
        mutated_key=encryptme.gen_mutated_key(key_64, epochs) # generate a mutated key from the 64 bit key and number of epochs
        encrypted_chunk_array=utils.gen_chunk_array_from_encrypted(msg) # generate an encrypted chunk array from the message string
        decrypted_chunk_array = encryptme.chunk_array_decrypt(encrypted_chunk_array,mutated_key,epochs) # decrypt the chunk array
        decrypted_message=utils.decrypted_chunks_to_string(decrypted_chunk_array) # generate a string from the decrypted chunks

        if DEBUG:
            print("DECRYPT -> input exchange key: "+str(key))
            print("DECRYPT -> number of epochs: "+str(epochs))
            print("DECRYPT -> mutated key: "+str(mutated_key))
            print("DECRYPT -> encrypted chunk array: "+str(encrypted_chunk_array))
            print("DECRYPT -> decrypted chunk array: "+str(decrypted_chunk_array))
            
        return decrypted_message # return the decrypted message

    @staticmethod
    # encrypted_chunk_array -> int[], mutated_key -> int, epoch -> int
    def chunk_array_decrypt(encrypted_chunk_array, mutated_key, epochs): # decrypt a chunk array with a 64 bit key and an number of epochs
        decrypted_chunk_array=encrypted_chunk_array # initialise decrypted chunk array to encrypted chunk array (will be iteratively updated)
        new_key_64 = mutated_key                    # initialise new key to current key (will be iteratively updated)

        epoch_counter=epochs-1            # start at number of epochs -1, as when encryption is done, the epoch counter is increased every loop (we are reversing encryption)
        for epoch in range(epochs):       # decrypt epoch number of times
            decrypted_chunk_array, new_key_64 = encryptme.epoch_decrypt(decrypted_chunk_array,new_key_64,epoch_counter) # get decrypted chunks and key
            epoch_counter-=1              # as we are decrypting, we decrease the epoch counter
        return decrypted_chunk_array      # return the decrypted chunk array

    @staticmethod
    # encrypted_chunk_array -> int[], new_key_64 -> int, epoch_counter -> int
    def epoch_decrypt(encrypted_chunk_array,new_key_64,epoch_counter): # decrypt a chunk array at a specific epoch
        new_chunk_array=[]                                  # each epoch generates a new chunk array
        new_key=new_key_64                                  # each epoch generates a new key
        epoch_key = utils.gen_64_block(epoch_counter*epoch_counter, 1) # generate a new epoch key, it converts the epoch count to binary and pads it with 1s
        new_key=new_key^epoch_key                           # xor the passed in key with the epoch key, do this at the start as we are reversing the order of the encryption

        reversed_array=encrypted_chunk_array                # reverse the array to perform easy operations on it
        reversed_array.reverse()                            # ''
        for i in range(len(reversed_array)):                # loop through each chunk
            if i != len(reversed_array)-1:                  # not reached the first last chunk in the reversed array
                new_chunk_array.append(reversed_array[i]^reversed_array[i+1]) # append the new chunk array with the current chunk xored with the next chunk in the reversed array
            else:                                           # reached the last chunk
                new_chunk_array.append(reversed_array[i])   # append new chunk array with this as it cant be xored with its non existent neighbour
            new_chunk_array[i]=new_chunk_array[i]^new_key   # xor the current chunk in the new array with the new key 
        # reversed_array.reverse()                          # dont know why, but sometimes it doesn't work without this... pls contact me if you know why
        new_chunk_array.reverse()                           # reverse the new chunk array to its original order
        return new_chunk_array, new_key                     # return the decrypted chunk array and key


    @staticmethod
    # key -> int, epoch -> int
    def gen_mutated_key(key,epochs): # generate a mutated key from an input key and number of epochs (basically replicate what encryption does to the key)
        mutated_key=key                                       # initalise the mutated key to the current key
        for epoch in range(epochs): # we loop over 'epochs' times to get the final key, then in decryption the first step is to revert the key back one step
            epoch_key = utils.gen_64_block(epoch*epoch, 1)    # generate a new epoch key, it converts the epoch count to binary and pads it with 1s
            mutated_key= mutated_key ^ epoch_key              # generate a new key by xoring the current key with the epoch key
        return mutated_key                                    # return the mutated key
