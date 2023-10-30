'''Module to generate OTP'''
import random
import string
import time


def generate_otp(otp_size = 6):
    """
    Function to generate an OTP code.
    """
    final_otp = ''
    for _ in range(otp_size):
        final_otp = final_otp + str(random.randint(0,9))

    current_time = time.time()
    expiration_time = current_time + 200
    return final_otp, expiration_time


def generate_password(length):
    '''
    Function to generate a random password
    '''
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string
