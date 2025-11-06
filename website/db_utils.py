import mysql.connector
from typing import Optional, Dict
from .app_config import *
import sys


def _get_conn(config: Dict) -> mysql.connector.MySQLConnection:
    print(f"{config}")
    return mysql.connector.connect(host = config["host"], 
                                   port = config["port"], 
                                   user = config["user"], 
                                   password = config["password"],
                                   database = config["database"],
                                   connection_timeout=5, )

def insert_user(username: str, salt_hex: str, mk_hash_hex: str) -> bool:
    try:
        # print(f"Inserting user: {username}, salt: {salt_hex}, mk_hash: {mk_hash_hex}")
        conn = _get_conn(REMOTE_DB) 
        cur  = conn.cursor() 

        cur.execute( "INSERT INTO users (username, salt, master_key_hash) VALUES (%s,%s,%s)", (username, salt_hex, mk_hash_hex))  

        conn.commit()  
        print(f"User {username} inserted successfully.")
        return True  
    
    except Exception as e:  
        sys.stderr.write(f"Error inserting user: {e}")
        raise e
    
    finally:
        print("Closing connection...")
        conn.close()  

def fetch_user(username: str) -> Optional[Dict]:
    conn = _get_conn(REMOTE_DB)
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT id, username, salt, master_key_hash FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def insert_secret(user_id: int, label: str, login_user: str, iv_hex: str, ciphertext_b64: str) -> None:
    conn = _get_conn(LOCAL_DB)  

    cur  = conn.cursor()  

    cur.execute("""INSERT INTO secrets (user_id, label, login_username, iv, ciphertext) VALUES (%s,%s,%s,%s,%s)""", 
                (user_id, label, login_user, iv_hex, ciphertext_b64))  
    
    conn.commit()  

    conn.close()  

def fetch_secrets(user_id: int):
    conn = _get_conn(LOCAL_DB)  

    cur  = conn.cursor(dictionary=True)  

    cur.execute("""SELECT id, label, login_username, iv, ciphertext FROM secrets WHERE user_id=%s""", (user_id,))  

    rows = cur.fetchall()  

    conn.close()  

    return rows  

def delete_secret_by_id(user_id: int, secret_id: int) -> None:  
    conn = _get_conn(LOCAL_DB)  

    cur = conn.cursor()  

    cur.execute("DELETE FROM secrets WHERE id=%s AND user_id=%s", (secret_id, user_id))  

    conn.commit()  

    conn.close()



