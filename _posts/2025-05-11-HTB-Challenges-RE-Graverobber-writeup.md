---
title: HTB Challenge RE Graverobber Writeup
date: 2025-05-11
categories: [CTF, HTB]
tags: [CTF, HTB, Challenges, RE, Very Easy]
description: HTB Challenge RE Graverobber Writeup
---
# Basic checks
- file information
![Screenshot](/assets/img/htb-challenges/re/graverobber-screenshot/image_1.png)

Trying to run the executable just returns an output string.
![Screenshot](/assets/img/htb-challenges/re/graverobber-screenshot/image_2.png){: .left}

# Disassemble
We will start by finding the output string in the disassembly and slowly trace back. The output is printed after checking the returning result of the "stat" function.
![Screenshot](/assets/img/htb-challenges/re/graverobber-screenshot/image_3.png){: .left}

Based on Google, the "stat" syscall in Linux is a function that returns metadata of a file, where the first argument is the file path (in this case local_58). From here I've renamed the variable to "file_path". Based on the manual page of "stat", the first argument should be a char array, so file_path should be a char array representing the file path.

Back tracking the file_path variable, we can see that the content of file_path is being set here.
![Screenshot](/assets/img/htb-challenges/re/graverobber-screenshot/iamge_4.png)

Most of the code is enclosed in a do while loop, where local_ec seems to be a counter of the loop (renaming it as "counter" here). In each loop, the counter is used as on offset to assign the content of file_path. The value assigned is retrieved from the "parts" section + a certain offset based on the counter.

Clicking on the "parts" variable takes us to a data section with a large block of bytes. Judging by the first few non-zero byte values, this seems to be the ASCII value of the flag starting with "485442" (which is "HTB" in hex).
![Screenshot](/assets/img/htb-challenges/re/graverobber-screenshot/image_5.png)

Looking back at the value assignment part, the "parts" data section was accessed with the offset of "counter" + 4. This means that it's skipping 3 bytes and only fetching every 4th byte in the data section. So it seems that the file_path variable is constructed based on the flag itself.
# Code flow
Based on these information discovered, the code seems to be doing the following steps:
1. Get the hex value from "parts" data section and append it to the "file_path" array.
2. Append the "/" character to "file_path" array.
3. Call "stat" with "file_path" as the file path.
4. Check if the provided file path exists.
	1. If the file path does not exist, print the error message and exit.
	2. If the file path exists, continue the loop.
5. Repeat the process for 32 times (0x1f). If the program reached this point without exiting, print the success message and exit.

Since the "path" data section stores the flag, we can simply dump the bytes from there and removing all null bytes to get the flag.
![Screenshot](/assets/img/htb-challenges/re/graverobber-screenshot/image_6.png)

We can also confirm the flow by creating the subdirectories using the flag and rerun the program to get the success message.
![Screenshot](/assets/img/htb-challenges/re/graverobber-screenshot/image_7.png)
