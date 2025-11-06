SHOW DATABASES;
CREATE DATABASE IF NOT EXISTS remote_KDB;
USE remote_KDB;
SHOW TABLES;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    salt VARCHAR(128),
    master_key_hash VARCHAR(128) NOT NULL
);


SHOW DATABASES;
CREATE DATABASE IF NOT EXISTS ciphervault;
USE ciphervault;

CREATE TABLE secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    label VARCHAR(100),
    login_username VARCHAR(128),
    iv VARCHAR(128),
    ciphertext VARCHAR(128)
);