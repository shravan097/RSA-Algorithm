#AUTHOR: SHRAVAN

from random import randrange, getrandbits

# Keeping track of Prime Numbers used so every users get unique prime numbers.
used_prime_number=[]

# RSA Encryption
# The User Data Access Object handles all interactions with the User collection.

class RSA_User:
    """ A RSA User Object for Encryption and Decryption.

        Attributes:
            get_public_key():  Returns public key of the given User
            encrypt(message):  Encrypts given message
            decrypt(message):  Decrypts given message


        Example:
            Alice= RSA_User("Alice")
            Bob= RSA_User("Bob")

            #Bob encrypts a message using Alice's public key
            bob_encrypted_msg= Alice.encrypt("Hey, Alice. I am Bob!")

            #Now Alice Decrypts Bob's Message Using Her Private Key
            decrypted_message= Alice.decrypt(bob_encrypted_msg)

            print(decrypted_message)

            """

    #STATIC METHODS

    # Fermat's Little Theorem Prime Test For Simplicity
    # There are cases where this test fails, Carmichael's Numbers, but  its rare
    #Fermat's Prime Test. Returns True if given number is a prime
    def __prime_test(number):
        if number is 2:
            return True
        return pow(2, number - 1, number) == 1

    # Generating Large Primes of at most 256 bit
    # 2048 Bit is reccomended according to wikipedia
    #Returns a prime number of given bit number.
    def __generate_prime(num_bit):
        prime_num = getrandbits(num_bit)
        while (not RSA_User.__prime_test(prime_num) and not(prime_num in used_prime_number)):
            prime_num = getrandbits(num_bit)
        used_prime_number.append(prime_num)
        return prime_num

    # EUCLIEDEAN ALGORITHM for finding greatest common divisor.
    #  Returns GCD of given two number
    def __gcd_euclidean(a, b):
        if (b == 0):
            return a
        else:
            return RSA_User.__gcd_euclidean(b, a % b)


    # Euler's Totient Function for prime.
    # Returns total number of relative prime < n
    def __euler_totient(p,q):
        return ((p - 1) * (q - 1))


    # Using Extended Euler's Algorithm ,we can find the multiplicative inverse quickly.
    # We use the fact that e*d=1 mod(euler_totient())
    def __extended_euclid(a,b):
        if b == 0:
            return (a, 1, 0)
        d, x, y = RSA_User.__extended_euclid(b, a % b)
        return d, y, x - (a // b) * y




    # OBJECT METHOD

    #Constructor for the class
    def __init__(self, name):
        self.name = name
        self.__p=RSA_User.__generate_prime(256)
        self.__q=RSA_User.__generate_prime(257)


    def get_public_keys(self):
        """Public Key Functions

            Returns e and n

            Example:
                Alice = RSA_User("Alice")
                e,n= Alice.get_public_keys()
            """
        n=(self.__p)*(self.__q)
        for coprime in range(3, n, 2):
            if (RSA_User.__gcd_euclidean(coprime, RSA_User.__euler_totient(self.__p,self.__q)) is 1):
                return coprime,n

    #PRIVATE Object's Method
    def __get_private_key(self):
        e,n=self.get_public_keys()
        #Phi represents thhe Euler Totient function
        phi=RSA_User.__euler_totient(self.__p,self.__q)
        x, y, z = RSA_User.__extended_euclid(e,phi)
        if (not (y > 0)):
            return (phi + y),n
        else:
            return y,n

    def encrypt(self,message):
        """Encrypts the given message.

            Here Jack will Use Alice's public key to encrypt his message.
            Then Jack sends the encrypted_message to Alice.
            This function is public and available to use by anyone.

            Example:
                Alice = RSA_User("Alice")
                Jack= RSA_User("Jack")
                Jack_encrypted_message= Alice.encrypt("Hey Alice, This is Jack!")

        """
        e,n=self.get_public_keys()
        uncipher = []
        ciphered = []

        for character in message:
            uncipher.append(ord(character))

        for unciphered in uncipher:
            ciphered.append(pow(unciphered, e, n))

        return ciphered


    def decrypt(self, message):
        """Decrypts the given message.

            Here Alice will use her private key to decrypt Jack's message.
            Then Jack sends the encrypted_message to Alice.
            This function is private and ONLY the Alice can use this.
            Other keys will not work and throw an execption with error message.

            Example:
                Alice = RSA_User("Alice")
                Jack= RSA_User("Jack")
                Jack_encrypted_message= Alice.encrypt("Hey Alice, This is Jack!")
                print("Message = ",Alice.decrypt(Jack_encrypted_message))
        """
        try:
            d,n=self.__get_private_key()
            uncipher = []
            deciphered = []

            real_message = ""

            for character in message:
                uncipher.append(character)

            for unciphered in uncipher:
                deciphered.append(pow(unciphered, d, n))

            for things in deciphered:
                 real_message += chr(things)

            return real_message
        except Exception as e:
            print("Something Went Wrong....Did you use the right key?.")
            print("Error Report :", e)

