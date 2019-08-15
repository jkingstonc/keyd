# James Clarke 02/02/2019
# Example file for keyd1

from keyd import keyd # import the keyd file from the keyd library

user1 = keyd.keyd_node() # create user 1
user2 = keyd.keyd_node() # create user 2

user1.init_exchange(user2.get_public_key()) # initialise an exchange, from user 1 to user 2
user2.init_exchange(user1.get_public_key()) # initialise an exchange, from user 2 to user 1

message = "hello there"

encrypted=user1.encrypt(message,user2.get_public_key()) # user 1 encrypts a message to send to user 2
decrypted=user2.decrypt(encrypted,user1.get_public_key()) # user 2 decrypts a message recieved from user 1

user1.close_exchange(user2.get_public_key()) # user 1 closes the exchange with user 2
user2.close_exchange(user1.get_public_key()) # user 2 closes the exchange with user 1


print("user1: message to send:   "+message)
print("user1: message encrypted: "+encrypted)
print("user2: message recieved:  "+encrypted)
print("user2: message decrypted: "+decrypted)