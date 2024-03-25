# Joshua Sterken 10982790
# Foundations of Cybersecurity
# Programming Assignment 1
# March 1, 2024
# Program sets up 2 HTTP endpoints, one that sends back a JWT,
# and another that sends back the JWKS of all requested JWK's

import time
import base64
from flask import Flask, request, jsonify
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sqlite3

app = Flask(__name__)

# place to store the keys (JWK, not the public_key or private_key)
# ***Key is not actually stored in JWK just a representation***)
keys = []

# initializes the database
def startDB():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    # conn.execute(
    #     'CREATE TABLE IF NOT EXISTS privateKeys (kid REAL, key BLOB, alg TEXT, kty TEXT, use TEXT, n TEXT, e TEXT, exp TEXT)'
    # )
    conn.execute(
        'CREATE TABLE IF NOT EXISTS privateKeys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)'
    )
    conn.commit()
    conn.close()


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # common default
        key_size=2048,  # common default
        backend=default_backend(),  # don't need to specify, can use default
    )
    public_key = (
        private_key.public_key()
    )  # generate the public key from the private key

    n = public_key.public_numbers().n  # modulus
    e = public_key.public_numbers().e  # exponent

    # encoding the keys into proper format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem, n, e

def generate_keys_for_testing():
   #generate a key that will expire in 1 hour
    private_pem, public_pem, n, e = generate_key_pair()
    expiry = time.time() + 3600  # 1 hour expiration
    #save to database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    conn.execute('INSERT INTO privateKeys (key, exp) VALUES (?, ?)',(private_pem, expiry))
    conn.commit()
    conn.close()

    #generate a key that has already expired
    private_pem, public_pem, n, e = generate_key_pair()
    expiry = time.time() - 3600  # expired
    #save to database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    conn.execute('INSERT INTO privateKeys (key, exp) VALUES (?, ?)',(private_pem, expiry))
    conn.commit()
    conn.close()


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    # filter out any expired keys and add to list tmp
    tmp = []
    
    # connect to database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('SELECT kid, key, exp FROM privateKeys WHERE exp > ?', (time.time(),))
    data = cursor.fetchall()
    conn.close()

    private_pem = data[1]
    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )

    n = private_key.public_key().public_numbers().n
    e = private_key.public_key().public_numbers().e

    # convert n and e to base64 url safe
    n_byte_array = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big", signed=False)
    n_base64_str = base64.urlsafe_b64encode(n_byte_array).decode("utf-8").rstrip("=")
    # print(f"n = {n_base64_str}")
    e_byte_array = e.to_bytes((e.bit_length() + 7) // 8, byteorder="big", signed=False)
    e_base64_str = base64.urlsafe_b64encode(e_byte_array).decode("utf-8").rstrip("=")
    # print(f"e = {e_base64_str}")

    for kid, exp in data:
        tmp.append(
            {
                "kid": kid,
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "exp": exp,
                "n": n_base64_str,
                "e": e_base64_str,
            }
        )
    
    # for jwk in keys:
    #     if (
    #         jwk["exp"] > time.time()
    #     ):  # if the expiration time is more than the current time add to list
    #         tmp.append(jwk)

    jwks = {
        "keys": tmp
    }  # add filtered list of jwk's (tmp) to jwks under "keys" key per spec

    # return JWKS and staus code of 200
    return jsonify(jwks), 200


@app.route("/auth", methods=["POST"])
def auth():
    # # using time to set expiration and generate a unique kid
    # kid = str(
    #     float(time.time())
    # )  # had as int, set to float, thought maybe the time wasn't precise enough to have distinct kids
    # expiry = time.time() + 3600  # 1 hour expiration
    
    
    
    now = time.time()

    # generate key pair -- private pem used for signing, don't think i need public_pem ?
    # private_pem, public_pem, n, e = generate_key_pair()

    # connect to database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    # if expired='true' pull an expired key from the database else pull a non-expired key
    if request.args.get("expired"):
        cursor.execute('SELECT kid, key, exp FROM privateKeys WHERE exp <= ?', (now,))
    else:
        cursor.execute('SELECT kid, key, exp FROM privateKeys WHERE exp > ?', (now,))

    data = cursor.fetchone()
    conn.close()

    kid = data[0]
    private_pem = data[1]
    expiry = data[2]
    # private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())

    # # convert n and e to base64 url safe
    # n_byte_array = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big", signed=False)
    # n_base64_str = base64.urlsafe_b64encode(n_byte_array).decode("utf-8").rstrip("=")
    # # print(f"n = {n_base64_str}")
    # e_byte_array = e.to_bytes((e.bit_length() + 7) // 8, byteorder="big", signed=False)
    # e_base64_str = base64.urlsafe_b64encode(e_byte_array).decode("utf-8").rstrip("=")
    # # print(f"e = {e_base64_str}")

    # # save to database
    # conn = sqlite3.connect('totally_not_my_privateKeys.db')
    # # conn.execute('INSERT INTO privateKeys (kid, key, alg, kty, use, n, e, exp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',(kid, private_pem, "RS256", "RSA", "sig", n, e, expiry))
    # conn.execute('INSERT INTO privateKeys (key, exp) VALUES (?, ?)',(private_pem, expiry))
    # conn.commit()
    # conn.close()

    # pull from database

    # # store keys with kid and expiry in the list keys
    # # will become the value for key "keys" in jwks
    # keys.append(
    #     {
    #         "kid": kid,
    #         "alg": "RS256",
    #         "kty": "RSA",
    #         "use": "sig",
    #         "n": n_base64_str,
    #         "e": e_base64_str,
    #         "exp": expiry,
    #     }
    # )

    # create and sign JWT token to be returned to requester
    token = jwt.encode(
        {  # jwt.encode does the signing
            "exp": expiry,
            "iss": "Yours truly",
            "iat": time.time(),
        },
        private_pem,
        algorithm="RS256",
        headers={
            "kid": kid,
            "alg": "RS256",
            "typ": "JWT",
            "kty": "RSA",
            "use": "sig",
            # "n": n_base64_str,
            # "e": e_base64_str,
        },
    )

    # print(f"\n\nToken: {token}\n\n")
    # return the JWT token and status code of 200
    return jsonify({"token": token}), 200


if __name__ == "__main__":
    #start database
    startDB()
    #generate keys for testing
    generate_keys_for_testing()
    app.run(port=8080)
