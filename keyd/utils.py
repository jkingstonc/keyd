CHAR_ENCODE_LENGTH=3  # number of digits representing 1 character
CHUNK_SIZE = 20 # number of digits in a non-encrypted chunk
CHUNK_BREAKER = '-'

def exp_by_squaring(x, n): # exponential by squaring: fast algorithm
    if n < 0:
        return exp_by_squaring(1 / x, -n)
    elif n == 0:
        return  1
    elif n == 1:
        return  x
    elif n %2 ==0:
        return exp_by_squaring(x * x,  n / 2)
    elif n %2 != 0:
        return x * exp_by_squaring(x * x, (n - 1) / 2)

# generate a string from an encrypted chunk array
def encrypted_chunks_to_string(chunk_array):
    string=""                               # initialise string
    for chunk in range(len(chunk_array)):   # loop through each chunk
        string+=str(chunk_array[chunk])     # append the string with the current chunk 
        if chunk != len(chunk_array)-1:     # if we havent reached the last chunk then add a chunk breaker
            string+=CHUNK_BREAKER
        
    return string # return the string

# generate a string from a decrypted chunk array
def decrypted_chunks_to_string(chunk_array):
    string=""                   # initialise an string
    for chunk in chunk_array:   # loop through each chunk
        string+=str(chunk)      # add the chunk to the string
    return encrypted_integer_to_string(int(string)) # convert the string (actually a number) to a decoded string

def str_to_int(string): # return a string as an integer
    str_int=""
    for char in string:
        str_int+=str(char_to_int(char))
    return int(str_int) # if str_int is blank, this will fail

def encrypted_integer_to_string(i): # used to turn an integer (from decrypted chunks) into a readable string ( hopefully a message ;) )
    int_as_string = str(i)          # convert the integer to a string to manipulate
    num_chars = len(int_as_string)//CHAR_ENCODE_LENGTH # number of full characters that are encoded in the integer (should be the same as the length of the integer)
    num_remaining_digits=len(int_as_string)%CHAR_ENCODE_LENGTH # number of remaining characters, that havent been decoded properly
    string=""                       # string to add to
    char_counter=0                  # which character we are processing
    for three_digit in range(num_chars): # loop through the number of characters
        three_digit_number=str(int_as_string)[ # get the next 3 digit number from the integer string, by stripping the string at the char_counter index
            char_counter*CHAR_ENCODE_LENGTH:(char_counter*CHAR_ENCODE_LENGTH)+CHAR_ENCODE_LENGTH
            ]
        character=int_to_char(int(three_digit_number)) # get the character from the character dictionary
        string+=character # append the string with this character
        char_counter+=1 # append the character counter
    if num_remaining_digits > 0: 
        pass # THERE HAS BEEN AN ENCODING ERROR, LIKELY FROM AN INTRUDER
    return string # return the decoded string

# generate a 64 bit integer block from an integer, and pad the front with the specified padding
def gen_64_block(i, padding):
    binary_integer='{:b}'.format(i)                   # binary version of integer
    bit_len = len(binary_integer)                     # get length of key in bits
    if bit_len > 64:                                  # check if the integer is greater than 64 bit   
        return int(binary_integer[:-(bit_len-64)],2)  # return the integer, removing the last n digits to make it 64 bit
    required_bits=64-bit_len                          # get the number of bits needed to be added
    padded_string = ''.join(str(padding) for x in range(required_bits)) # generate a string of 1s to pad the front of the binary number
    block_64 = padded_string+binary_integer           # add the two strings together
    return int(block_64,2)                            # return the key in base 10

# used to generate an array of chunks from a message
def gen_chunk_array(string):
    string_as_int = str_to_int(string)                       # convert the message to a single integer
    num_full_chunks = len(str(string_as_int))//CHUNK_SIZE    # work out how many full chunks (full remainder of length / chunk size)
    num_remaining_digits=len(str(string_as_int))%CHUNK_SIZE  # get number of remaining digits from the number
    chunk_array=[]                                           # chunk array to be added to
    chunk_counter=0                                          # how many chunks
    for chunk in range(num_full_chunks):                     # loop through each full chunk
        number_as_string=str(string_as_int)[                 # get the digits at the next chunk position, and number of digits as chunk size, using string slicing
            chunk_counter*CHUNK_SIZE:(chunk_counter*CHUNK_SIZE)+CHUNK_SIZE
            ]
        chunk_array.append(int(number_as_string))            # append this new number to the chunk array
        chunk_counter+=1                                     # increase the chunk counter
    if num_remaining_digits > 0:                             # if there are remaining digits
        chunk_array.append(int(str(string_as_int)[chunk_counter*CHUNK_SIZE:])) # add these remaining digits, using string slicing and indexing, to the chunk array
    return chunk_array # return the chunk array

# take an integer (typically from an encryption) and turn it into a chunk array
def gen_chunk_array_from_encrypted(msg):
    chunk_array=[]                                # initialise chunk array
    char_counter=0                                # initialise char counter
    while char_counter < len(msg):                # while we havent reached the end of the message
        new_chunk=""                              # initialise new chunk
        
        while msg[char_counter] != CHUNK_BREAKER: # while we havent reached a chunk breaker
            new_chunk+=msg[char_counter]          # add the next digit to the chunk 
            char_counter+=1                       # increase the character counter

            if char_counter== len(msg):           # if we have reached the end of the message then we break as we dont want any failing indexes
                break
            
        if new_chunk != '':                       # check if the new chunk isn't null
            chunk_array.append(int(new_chunk))    # append the chunk array with the new chunk
            char_counter+=1                       # increase the character counter to skip the chunk breaker
    return chunk_array # return the chunk array

def char_to_int(char): # map characters to a unique 3 digit integer
    values = {
        'a': 171,
        'b': 328,
        'c': 113,
        'd': 912,
        'e': 238,
        'f': 752,
        'g': 623,
        'h': 257,
        'i': 122,
        'j': 344,
        'k': 123,
        'l': 111,
        'm': 643,
        'n': 777,
        'o': 435,
        'p': 961,
        'q': 444,
        'r': 121,
        's': 632,
        't': 915,
        'u': 354,
        'v': 543,
        'w': 693,
        'x': 345,
        'y': 346,
        'z': 234,
        '0': 672,
        '1': 664,
        '2': 128,
        '3': 984,
        '4': 982,
        '5': 655,
        '6': 431,
        '7': 413,
        '8': 451,
        '9': 175,
        ' ': 489,
    }
    if char in values:
        return values[char]
    else:
        return 0

def int_to_char(i): # map integers to their specified character
    values = {
        171: 'a',
        328: 'b',
        113: 'c',
        912: 'd',
        238: 'e',
        752: 'f',
        623: 'g',
        257: 'h',
        122: 'i',
        344: 'j',
        123: 'k',
        111: 'l',
        643: 'm',
        777: 'n',
        435: 'o',
        961: 'p',
        444: 'q',
        121: 'r',
        632: 's',
        915: 't',
        354: 'u',
        543: 'v',
        693: 'w',
        345: 'x',
        346: 'y',
        234: 'z',
        672: '0',
        664: '1',
        128: '2',
        984: '3',
        982: '4',
        655: '5',
        431: '6',
        413: '7',
        451: '8',
        175: '9',
        489: ' '
    }
    if i in values:
        return values[i]
    else:
        return ""

    

