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
    salt_length = 8
    characters = string.ascii_letters + string.digits
    salt = ''.join(random.choice(characters) for i in range(salt_length))
    return salt

def check_password(password):
    if len(password) < 8:
        return False
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
    query = f"SELECT user_id, salt, hash FROM USERS WHERE USERNAME = '{username}' "

    try:
        DBCur.execute(query)
        row = DBCur.fetchone()
        if not row:
            conn.send("2".encode("UTF-8"))
            return None, None
        else:
            if varify_password(pwd,row[1],row[2]):
                conn.send("0".encode("UTF-8"))
                logging.info(f"{username} login, ID: {row[0]}")
                DBConn.commit()
                return row[0], username
            else:
                conn.send("3".encode("UTF-8"))
                return None, None

    except Exception:
        conn.send("404".encode("UTF-8"))
        DBConn.rollback()
        return None, None

def sign_up(conn,addr):
    username = conn.recv(4096).decode("UTF-8")
    pwd = conn.recv(4096).decode("UTF-8")
    query = f"SELECT salt FROM USERS WHERE USERNAME = '{username}' "

    try:
        DBCur.execute(query)
        row = DBCur.fetchone()
        if row:
            conn.send("2".encode("UTF-8"))
            return
        else:
            if check_password(pwd):
                conn.send("0".encode("UTF-8"))
                _salt = generate_salt()
                _hash = generate_sha256_hash(pwd+_salt)
                getId_query = f"SElECT MAX(user_id) From users"
                DBCur.execute(getId_query)
                row = DBCur.fetchone()
                if not row:
                    raise Exception
                userId = row[0]+1
                insert_query = f"insert into users(user_id, username, salt, hash) values({userId},'{username}','{_salt}','{_hash}')"
                DBCur.execute(insert_query)
                logging.info(f"New user {username} Sign up, ID: {userId}")
                DBConn.commit()
                return
            else:
                conn.send("3".encode("UTF-8"))
                return

    except Exception:
        conn.send("404".encode("UTF-8"))
        DBConn.rollback()
        return


def post_question(conn, addr, User_id):
    pass


def comm(conn,addr):
    User_id = None
    Username = None
    logging.info(f"Connect: {conn}")
    while True:
        try:
            function_number = conn.recv(4096).decode("UTF-8")
            if not function_number:
                continue
            elif function_number == "1":
                User_id, Username = login(conn,addr)

            elif function_number == "2":
                sign_up(conn,addr)

            elif function_number == "3" and User_id is not None:
                post_question(conn,addr,User_id)

            elif function_number == "4" :
                logging.info(f"{Username} logout, ID: {User_id}")
                User_id, Username = None ,None

            elif function_number == "0":
                logging.info(f"Disconnect: {conn}")
                break
        except Exception:
            break

    conn.close()

def run(ip = '127.0.0.1',port=8000): #Set default value of parameters

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Default protocol is TCP
    server.bind((ip, port))
    server.listen(200)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    ssl_socket = context.wrap_socket(server, server_side=True)
    pool = ThreadPoolExecutor(2000) # Use ThreadPoolExecutor to handle
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
    run()