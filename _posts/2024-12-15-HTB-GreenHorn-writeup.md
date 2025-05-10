---
title: HTB GreenHorn Writeup
date: 2024-12-15
categories: [CTF, HTB]
tags: [CTF, HTB, Easy]
description: HTB GreenHorn Writeup
---
# Recon
## Nmap
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
3000/tcp open  ppp?
```
## Port 80
Main web app (Pluck 4.7.8)
![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 2.png)

Potential Vulnerability
Pluck 4.7.8 RCE ([https://www.exploit-db.com/exploits/51592](https://www.exploit-db.com/exploits/51592))
- Requires Authentication
## Port 3000
Git Repository (Gitea 1.21.11)
![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 2.png)
Contains source code of the Pluck web app on port 80.

A hash can be found on [http://greenhorn.htb:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php](http://greenhorn.htb:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php)

![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 2.png)
Hash can be cracked with hashcat (-m 1700).
![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 3.png)

Password is used to login to Pluck on [http://greenhorn.htb/login.php](http://greenhorn.htb/login.php)

# User.txt
Manual exploit of the vulnerability ([Potential Vulnerability](/o/Og2iEqjeZhsUQ9WJ01Et/s/YLwrMFMuityftyQtpiNM/easy/greenhorn#potential-vulnerability)).
After login, visit "options" > "manage modules" > "Install a module...".

![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 4.png)

Create a PHP webshell, zip it and upload to the module installation page. The webshell will be loaded shortly after uploading.

![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 5.png)
The password found previously can be used to switch to user "junior".
![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 6.png)

# Root.txt
A PDF file can be found in /home/junior.
![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 7.png)

The PDF file contains instructions on running openvas as root user. A redacted password is included.
![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 8.png)

There are multiple tools on Github for bruteforcing the text redacted through pixelation. The one I used is Depix ([https://github.com/spipm/Depix](https://github.com/spipm/Depix)).
```
python3 depix.py -p ../blurred_password.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o output.png
```
The output shows readable text of the supposedly redacted password.
![Screenshot](/assets/img/htb-greenhorn-writeup-screenshot/image 9.png)
The password is then used to switch as user "root".

# Lesson Learned
## Do Not User Text Pixelation

From a person who has used text pixelation to redact sensitive information in images for a long time, this is a very interesting and important lesson. To know that pixelation can be easily reversed (or brute-forced) means that people should not be using this for redacting sensitive information in client reports. Images in this post was later edited to use blur instead of pixels for redaction.
