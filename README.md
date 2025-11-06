# Password Manager - Cipher-Dungeon 
#### **Note:** This README contains setup documentation with placeholder values.
#### Configure actual credentials in `.env` file (see `.env.example` for template).


### *** Digital Ocean Alma8 Droplet and MySQL remote server: ***
--------------------------------------------------------


### Updated GPG Key for packages
--------------------------------------------------------

rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux

dnf upgrade almalinux-release

yum clean all

yum makecache

Installed needed packages for Alma for base config 

yum install epel-release vim wget net-tools -y

vim /etc/sysconfig/selinux

"disable SELinux"

--------------------------------------------------------
### Installed iptables firewall and whitelisted IPs
--------------------------------------------------------

yum install iptables-services

systemctl start iptables

systemctl start ip6tables

systemctl enable iptables

systemctl enable ip6tables

systemctl enable iptables

systemctl enable ip6tables

iptables -nvL

ip6tables -nvL

--------------------------------------------------------
### Installed MySQL
--------------------------------------------------------

dnf update

dnf module list MySQL

dnf module enable mysql:8.0

dnf install mysql-server

systemctl start mysqld

systemctl enable mysqld

mysql_secure_installation

systemctl status mysqld

mysql -u root -p

--------------------------------------------------------
### Install Portknock
--------------------------------------------------------

dnf install knock-server

systemctl start knockd

systemctl enable knockd

--------------------------------------------------------
### MySQL DBs:
--------------------------------------------------------

### Vault:
--------------------------------------------------------
USN: Cipher Dungeon Vault

PSW: Your_Password_Here

--------------------------------------------------------
### MySQL KMS and Alma8 root user:
--------------------------------------------------------
USN: Cipher Dungeon KDB

PSW: Your_Password_Here

--------------------------------------------------------
### SSL Certificate Generations in CMD: 
--------------------------------------------------------
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

--------------------------------------------------------
### DB entries:
--------------------------------------------------------
fakeEmail1@email.com

Your_Password_Here

Wrong PSW: Wrong_Password_Here1

fakeEmail2@gmail.com 

Your_Password_Here

Wrong PSW: Wrong_Password_Here2

fakeEmail3@email.com

Your_Password_Here

Wrong PSW: Wrong_Password_Here3

fakeEmail4@

----------------------------------------------------------------------------------------

CREATE USER 'fakeEmail1'@'localhost' IDENTIFIED BY 'Your_DB_Password_Here';

CREATE USER 'fakeEmail1'@'%' IDENTIFIED BY 'Your_DB_Password_Here';

GRANT ALL PRIVILEGES ON *.* TO 'fakeEmail1'@'%' WITH GRANT OPTION;

FLUSH PRIVILEGES;

--------------------------------------------------------
### SSH Commands Windows cmd:
--------------------------------------------------------

ssh root@<IP Address> $<Password>>

Get to user fakeEmail1: mysql -u fakeEmail1 -p -h <IP Address> -P <Port>

PSW: Your_DB_Password_Here

Now in DB.

--------------------------------------------------------
### DB Test Cases: 
--------------------------------------------------------
"normal_user"

"user' OR '1'='1"

"user' --" 

"user' UNION SELECT * FROM users--"

"user'; DROP TABLE secrets--"
--------------------------------------------------------

https://www.lastpass.com/features/password-generator



