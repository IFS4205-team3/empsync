'''Module to send mail'''
import smtplib
import ssl
from .init_db import GMAIL_PASS

PORT = 465  # For SSL
SMTP_SERVER = "smtp.gmail.com"
SENDER_EMAIL = "empsyncmail@gmail.com"  # Enter your address

#config = configparser.ConfigParser()
#config.read('src/config.ini')
#PASSWORD = config.get('Password', 'GMAIL_PASS')

def send_reset(user_id, new_password):
    """
    Function to send reset password email
    """
    receiver_email = user_id  # Enter receiver address
    message = f"""\
    Subject: Empsync Password Reset

    Your new password is {new_password}
    Login to change your password.
    """

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, PORT, context=context) as server:
        server.login(SENDER_EMAIL, GMAIL_PASS)
        server.sendmail(SENDER_EMAIL, receiver_email, message)

def send_otp(user_id, otp_value):
    """
    Function to send OTP
    """
    receiver_email = user_id  # Enter receiver address
    message = f"""\
    Subject: Empsync Login OTP

    Your new One Time Password is {otp_value}
    """
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, PORT, context=context) as server:
        server.login(SENDER_EMAIL, GMAIL_PASS)
        server.sendmail(SENDER_EMAIL, receiver_email, message)
