'''Module to initilise Database'''
import os
import json
from sqlalchemy import create_engine, text
import sqlalchemy
from sqlalchemy.orm import sessionmaker, scoped_session
import hvac
from dotenv import load_dotenv
load_dotenv()


client = hvac.Client(url=os.getenv('VAULT_ADDR'))
client.token = os.getenv('VAULT_TOKEN')
read_response = client.secrets.kv.v2.read_secret_version(path='key')
aes_key=json.dumps(json.loads(json.dumps(read_response))['data']['data']['aes_key'])
AES_KEY = aes_key.replace('"', "")

database_url=json.dumps(json.loads(json.dumps(read_response))['data']['data']['database_url'])
DATABASE_URL = database_url.replace('"', "")

gmail_pass=json.dumps(json.loads(json.dumps(read_response))['data']['data']['gmail_pass'])
GMAIL_PASS = gmail_pass.replace('"', "")

cert_pem=json.dumps(json.loads(json.dumps(read_response))['data']['data']['cert_pem'])
CERT_PEM = cert_pem.replace('"', "")

key_pem=json.dumps(json.loads(json.dumps(read_response))['data']['data']['key_pem'])
KEY_PEM = key_pem.replace('"', "")

engine = create_engine(DATABASE_URL)

# test if connection is successful and if we are able to run connections
try:
    engine.connect()
    print("engine successfully connected to db")
    with engine.begin() as conn:
        result = conn.execute(text("SELECT * FROM employee")).fetchall()
except sqlalchemy.exc.SQLAlchemyError as err:
    print("engine failed to connect to db", err.__cause__)  # this will give what kind of error


db=scoped_session(sessionmaker(bind=engine))
a_session = db()
a_session.execute(text('CREATE EXTENSION IF NOT EXISTS pgcrypto'))
