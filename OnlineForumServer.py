import socket
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
import ssl
import psycopg2
import re
import random
import string
import hashlib
import logging

def setup_logging():

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='server.log',
        filemode='a'
    )

def generate_sha256_hash(_str):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(_str.encode('utf-8'))
    hash_result = sha256_hash.hexdigest()
    return hash_result

def generate_salt():
    password_length = 8
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for i in range(password_length))
    return password

def check_password(password):
    # Check if the password length is greater than or equal to 8
    if len(password) < 8:
        return False
    # Check for uppercase, lowercase, numbers and special characters
    pattern = '^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&,+-/;:| ])[A-Za-z\d@$!%*?&,+-/;:| ]+$'
    if re.match(pattern, password):
        return True
    else:
        return False

def varify_password(password,salt,Hash_Value):
    _hash = generate_sha256_hash(password+salt)
    return _hash == Hash_Value

def f_conn_handle():
    logging.info("One failed connection")

def login(conn,addr):
    username  = conn.recv(4096).decode("UTF-8")
    pwd = conn.recv(4096).decode("UTF-8")
    query = f"SELECT salt, hash FROM USERS WHERE USERNAME ={username}"

    try:
        DBCur.execute(query)
        row = DBCur.fetchone()
        if not row:
            conn.send("2".encode("UTF-8"))
            return
        else:
            if varify_password(pwd,row[2],row[3]):
                conn.send("0".encode("UTF-8"))
                return
            else:
                conn.send("3".encode("UTF-8"))
                return

    except Exception:
        conn.send("404".encode("UTF-8"))
        conn.rollback()
        return

def sign_up(conn,addr):
    pass

def comm(conn,addr):
    logging.info(conn)
    while True:
        try:
            function_number = conn.recv(4096).decode("UTF-8")
            if not function_number:
                continue

            elif function_number == "1":
                login(conn,addr)

            elif function_number == "2":
                sign_up(conn,addr)

            elif function_number == "0":
                break
        except Exception:
            continue
    conn.close()

def run(ip = '127.0.0.1',port=8000): #Set default value of parameters

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Default protocol is TCP
    server.bind((ip, port))
    server.listen(20)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    ssl_socket = context.wrap_socket(server, server_side=True)
    pool = ThreadPoolExecutor(200) # Use ThreadPoolExecutor to handle
    logging.info('Server started')
    while True:
        try:
            conn, addr = ssl_socket.accept()
            #Thread(target=comm, args=(conn,)).start()
            pool.submit(comm,conn,addr)
        except Exception:
            f_conn_handle()


if __name__ == '__main__':
    setup_logging()
    DBConn = psycopg2.connect(database="CyberSecurity", user="postgres", password="1234", host="localhost",port="5432")
    DBConn.autocommit = False
    DBCur = DBConn.cursor()
    clients=dict({})
    Clients_conn=dict({})
    run()