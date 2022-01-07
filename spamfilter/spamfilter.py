
#cryptograph library from https://pypi.org/project/pycrypto/
from Crypto.Hash import SHA256
from random import random

class spam_filter_client:

    def process_user_input(self):
        #Take input from user
        print('Enter your email address:')
        sender_email=input()

        print('Enter receiver email address')
        receiver_address=input()

        print('Enter message to send')
        message=input()

        self.computeHash(sender_email,receiver_address,message)
    
    
    def computeHash(self,sender_email,receiver_address,message):
        #convert information to bytes for easy hashing
        a_byte_array_sender_address=bytearray(sender_email,'utf8')
        a_byte_array_receiver_address=bytearray(receiver_address,'utf8')

        #variableto hold item to be hashed after extraction from arrays
        encryption_bytes=''


        #random number that will generate six zeroos for hash 256 string  
        rand_key_found=False
        
        #hash to be sent to server
        hash=''

        #A loop that will terminate when all six zeroos are found
        while not rand_key_found:
            for byte in range(0,len(a_byte_array_sender_address)-1):
                encryption_bytes += str(a_byte_array_sender_address[byte])

            for byte in range(0,len(a_byte_array_receiver_address)-1):
                encryption_bytes +=str(a_byte_array_receiver_address[byte])
            
            #Generate Random number for use
            random_num_for_sender_mail_bytes=bytearray(str(random()),'utf8')

            for byte in range(0,len(random_num_for_sender_mail_bytes)-1):

                hash_required_by_server=str(random_num_for_sender_mail_bytes[byte])
                encryption_bytes +=hash_required_by_server

            #perfoming actual hashing
            hash_for_spam_filter = SHA256.new()
            hash_for_spam_filter.update(encryption_bytes.encode('utf8'))
            computed_hash=hash_for_spam_filter.hexdigest()
            print(computed_hash)

            computed_hash_length=len(computed_hash)
            
            #variable to count zeros
            countZeros=0

            for count in range(computed_hash_length-1,computed_hash_length-6,-1):
                try:
                    value=int(computed_hash)
                    if value==0:
                        countZeros +=1
                except:
                    continue
            
            if countZeros==6:
                rand_key_found=True
        
        server=spam_filter_server()
        server.verify_random_key(sender_email,receiver_address,message,hash_required_by_server)
        


class spam_filter_server:
    
    def verify_random_key(self,sender_mail,receiver_mail,message,random_key):
        
        #convert information to bytes for hashing
        sender_email_bytes=bytearray(sender_mail,'utf8')
        receiver_email_bytes=bytearray(receiver_mail,'utf8')

        #variableto hold all the data to be encrypted with SHA256
        server_encryption_bytes=''

        for byte in range(0,len(sender_email_bytes)-1):
                server_encryption_bytes += str(sender_email_bytes[byte])

        for byte in range(0,len(receiver_email_bytes)-1):
                server_encryption_bytes +=str(receiver_email_bytes[byte])
        
        #add received random key to bytes to be encrypted
        server_encryption_bytes +=random_key
        
        #check if encryption will yield hash that ends with six zeroos
        server_hash_for_spam_filter = SHA256.new()
        server_hash_for_spam_filter.update(server_encryption_bytes.encode('utf8'))
        server_computed_hash=server_hash_for_spam_filter.hexdigest()

        
        server_computed_hash_length=len(server_computed_hash)
            
        #variable to count zeros
        server_count_zeros=0

        for count in range(server_computed_hash_length-1,server_computed_hash_length-6,-1):
            try:
                value=int(server_computed_hash[count])
                if value==0:
                  server_count_zeros +=1
            except:
                continue
            
            if server_count_zeros==6:
                print(message,'\n','sent successully...','\n','To:',receiver_mail)


client=spam_filter_client()
client.process_user_input()