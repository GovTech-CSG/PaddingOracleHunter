from Crypto.Cipher import AES
from flask import Flask, request
import rsa
import json
import binascii
from cryptography.hazmat.primitives import padding

#RSA
with open("keys/attacker_rsa", "rb") as f:
    RSA_PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(f.read())

with open("keys/attacker_rsa.pub", "rb") as f:
    RSA_PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())

#AES
key = 'This is a key123'
#IV = 'This is an IV456'
BLOCK_SIZE = 128

app = Flask(__name__)

def Aes_decrypt(ciphertext):
    iv = ciphertext[:16]    
    cipher = AES.new(key=key.encode(), mode=AES.MODE_CBC, IV=iv)
    decrypted_text = cipher.decrypt(ciphertext[16:])
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    try:        
        return unpadder.update(decrypted_text) + unpadder.finalize()
    except ValueError as e:    
        return None

def Rsa_decrypt(ciphertext):   
    try:       
        return rsa.decrypt(ciphertext, RSA_PRIVATE_KEY)
    except rsa.pkcs1.DecryptionError as e:
        return None


@app.route("/")
def index():
    msg = 'This server is use to simulate padding oracle attack on RSA PKCS#1 v1.5 padding at endpoint <b>/TestRsaPKCS1_5</b> and AES PKCS#7 padding at endpoint <b>/TestAesPKCS7</b><br><br>'\
    'Usage:<br>'\
    'curl -X POST -d ciphertext=ciphertextinhex http://localhost:8000/endpoint<br><br>'\
    'Ciphertext Sample:<br>'\
    'Rsa: c1d9cab61ccd343cbca9c6dba5c750f26094616b4a7b69d12944d240a3681cd2<br>'\
    'AES: 5468697320697320616e204956343536e56e85414c2907986bc61f535bbd296947f6730cb4e85d83daba77e959a8a25bbd6f09b1e44b2e0ccb513bd87fb935db<br><br>'\
    ''
    return msg

@app.route("/TestAesPKCS7", methods=["POST"])
def TestAesPKCS7():    
    plaintext = Aes_decrypt(binascii.unhexlify(request.form.get("ciphertext")))
    if plaintext is None:
        return "Invalid Padding"    
    else:
        try:
            data = json.loads(plaintext)
            if data['isAdmin'] == "True":
                return "You login as admin!"
            else:
                return "You login as normal user!"
        except:
            return "Invalid JSON"           


@app.route("/TestRsaPKCS1_5", methods=["POST"])
def TestRsaPKCS1_5():    
    plaintext = Rsa_decrypt(binascii.unhexlify(request.form.get("ciphertext")))
    if plaintext is None:
        return "Invalid Padding"    
    else:
        return "Success"    