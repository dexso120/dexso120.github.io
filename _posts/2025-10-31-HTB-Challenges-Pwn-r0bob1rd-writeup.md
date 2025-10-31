---
title: HTB Challenge Pwn r0bob1rd Writeup
date: 2025-10-31
categories: [CTF, HTB]
tags: [CTF, HTB, Challenges, Pwn, Very Easy]
description: HTB Challenge Pwn r0bob1rd Writeup
---

Note: I did use writeups from other people to guide myself through the challenge, so the writeup solution is not entirely unique. References are included at the end of this blog.
# Basic checks
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_1.png)

Note that security features such as Stack Canary, Non-executable stack and Partial RELRO are enabled. These will affect on how we can abuse the vulnerability found in this challenge.

# Identifying Vulnerability
We will start by looking at the disassembly using IDA free. Since the binary is not stripped, we can directly follow the symbol "main" to look at the flow of the main function.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_2.png)

## Not so useful functions
The function names `ignore_me_init_buffering` and `ignore_me_init_signal` pretty much describes what it does exactly, which is just initializing buffers and registering signal handlers which can be ignored as they are not important for this challenge. The function `banner` also just simply prints a banner ASCII art in the terminal which can be ignored as well.

The function `printRobobirds` starts by printing out a table containing names of Robobirds along with the associate ID for each of them.
## Vulnerable Function
Then the `operation` function was called, where the main vulnerability lies. The program starts off by asking the use to select a Robobird based on its ID. After entering the ID, the program will prompt the user to enter a description for the Robobird. And after a short delay, the user's input string is printed out on the terminal.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_3.png)

### Vulnerability 1 (Stack Overflow)
Looking at documentation of `fgets`, it states that the second argument provided (aka `rsi`) specifies how many characters (or bytes) will be readed from the given file stream. In this case, it is trying to read `0x6A` (or `106` in decimal) characters from `stdin` (in `rdx`) and write it to the local variable `[rbp+s]` (in `rdi`).

If we look back at the start of `operation`, we can see the size of each local variable that are allocated on the stack. The variable `s` is at offset `-70h` from the stack pointer. Since `var_8` is before `s`, this tells that the variable `s` has size of `70h - 8h = 68h` bytes. This mismatch in buffer size suggests that there is a **Stack Overflow** issue here.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_4.png)

However, recall that the binary has implemented Stack Canary, which will force the program to exit if it detects a corruption in the canary. In fact, the `var_8` is exactly the stack canary, where the value is obtained from the register `fs:28h`. The variable is placed exactly between the variable `s` and the return address of `operation`. This can be proved by attempting to enter a description with `104` (or `0x68`) characters.

![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_5.png)

In order to directly exploit this buffer overflow vulnerability, we will have to find a way to overwrite the return address without corrupting the stack canary which is quite difficult to do. Fortunately this will not be the route we take here.
### Vulnerability 2 (Format String)
Another vulnerability lies in the fact that the user input (saved in the variable `s`) is directly passed as the format argument of `printf()`.

![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_6.png)

This means that if a user includes a format specifier (e.g. `%x`), `printf()` will treat it exactly as a format specifier and attempts to replace it with additional argument provided to `printf()`. However, there are no additional argument provided to `printf()` in this case. So `printf()` will actually start replacing the format specifiers with values on the stack, which can cause unexpected data leakage.

This can be tested by using the `%x` specifier, which prints the value on the stack in hexadecimal format.

![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_7.png)
# Crafting Exploitation
General steps of the exploitation: 
1. Overwrite the GOT (Global Offset table) entry of `__stack_chk_fail` to `main` (causing infinite loop when stack overflows).
2. Leak the base address of `libc`.
3. Using return to libc to execute a user shell.
## Overwriting GOT
Firstly, we'll need to find the addresses of `__stack_chk_fail` and `main` in the `got.plt` table. To do this we will use `pwndbg` to debug the binary.

```bash
gdb-pwndbg ./r0bob1rd

# In Pwndbg, start program and break at the start
starti
```

We will start by disassembling the `__stack_chk_fail` function.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_8.png)

Here we can see a small stub which jumps to the GOT entry of `__stack_chk_fail`. While `pwndbg` automatically shows the address it's jumping to, we can also just calculate it based on the assembly instruction, which will be `0x400780 (rip) + 0x2018a2 = 0x602028`.

Similarly, we can just get the address of `main` directly without the jumping.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_9.png)

Now we have the following addresses:
```python
stack_chk_fail_addr = 0x602028 # Where the GOT entry is
main_addr = 0x400c0f # We'll overwrite the GOT entry with this value
```

Next we'll have to find the offset for the format string to access our input on the stack. This is just an trial and error process by providing a number of `%x` specifier along with some characters to identify the offset. From the example below, we can see that it takes 8 `%x` specifiers until we see the bytes `41414141` which corresponds to the `AAAA` in the format string we provided.

![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_10.png)

With the offset found, we can then use the `%n` specifier to write to arbitrary addresses. When using `%n`, it will attempt to write the number of bytes printed before the `%n` to the address specified by the optional arguments. For example, the below snippet will write the value `4` to `num`.
```C
int num;
printf("AAAA%n", &num);
```

In our exploitation, this means that we can provide the address of `__stack_chk_fail` and use `%n` to overwrite the target address.

### Mistake 1
So at first I attempted to follow common tutorials on simple format string exploit to craft my testing payload just to overwrite the target address with random values. The payload below should put the address `0x602028` (little endian) onto the stack at the 8th offset. And `%8$n` should then write the value `4` to the 8th offset (aka `0x602028`) as 4 bytes were printed before `%8$n`.
```python
b"\x28\x20\x60\x00%8$n"
```

However, I've forgotten 2 things here. One is that we are dealing with a 64-bit binary, so the address should be padded as `\x28\x20x\60\x00\x00\x00\x00\x00` instead. But more importantly, I forgot that C strings are null terminated, which means that when `printf()` tries to print the string above, it will stop at `\x00` and never reach the `%8$n` specifier to perform the overwriting.

### Fixing the payload
With some googling, I've found this video quite helpful [https://www.youtube.com/watch?v=9SWYvhY5dYw](https://www.youtube.com/watch?v=9SWYvhY5dYw) on explaining the details of format string vulnerability. The conclusion is to simply put the format specifier in front of the target address so the overwrite action will perform before `printf()` reaches the null byte. The video also explains on how should the offset be adjusted since we are placing the target address further on the stack.

So our goal is to write `0x400c0f` to the address `0x602028`. To write `0x400c0f`, we'll first convert it to decimal value (which is 4,197,391) and use the `%...x` specifier to print that many characters out  and use `%n` to write the value into `0x602028`.

```python
b"%4197391x%8$n\x28\x20\x60\x00\x00\x00\x00\x00"
```

Again, we'll need to adjust the offset since the address is no longer on offset 8. To calculate the new offset, we'll need to see how many characters there are before the first byte of the address. In the case above, the string `%4197391x%8$n` is 13 characters. As it is a 64-bit binary, the address will increment after 8 bytes (or 8 characters) of data. But since we can't specify an offset of 9 and a half, we'll need to pad it so that it's 16 characters before `\x28`. After padding it, the offset of the address should be at 10. The final payload is shown below.

```python
b"%4197391x%10$nAA\x28\x20\x60\x00\x00\x00\x00\x00"
```

Now we are able to overwrite the `__stack_chk_fail` GOT entry such that when a buffer overflow happens, it will simply go back to the start of this program. And since we want to trigger a buffer overflow, we'll need to further pad the payload above to reach 104 characters in total.

## Leaking libc Base Address
Next we will need to find the base address of libc that is running on the server. It is most likely that the libc base address will be reloacted for each new process. Therefore, we will need to find the base address at runtime by leaking it using the format string vulnerability.

First, we'll use the `%p` specifier to print stack values as a pointer. Based on the result, we can see the first and third value looks to be some kind of address.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_11.png)

If we set a breakpoint at `*0x400bf3` (aka when `printf()` is called), step into `printf()` and step through a few instructions, we can see that a few similar values are indeed on the stack. Note that the exact address is different since libc is relocated every time I run the binary.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_12.png)

You can also check the stack by dumping it directly.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_13.png)

By dumping the address mapping in pwndbg, we can see that the 2 addresses belongs to the libc library.
![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_14.png)

While the base address of libc may change, the offset between the base address and the leaked addresses do not change. So if we can calculate the offset of either address from the base address, we can simply calculate the base address of libc at runtime after leaking the base address. The offset calculation is shown below.
```
0x7ffff7e22723 - 0x00007ffff7c35000 = 0x1ed723
```

## Finding Gadgets to Spawn Shell
While googling about format string vulnerabilities, most of the blogs mentioned about building a ROP chain buy putting multiple ROP gadgets onto the stack and hijack the execution flow. However, I don't think it is really possible to do so in this case, since we cannot directly overflow the stack (because of stack canary) or overwrite the return address through format strings.

Based on other writeups, the answer seems to be relying on the one_gadget tool [https://github.com/david942j/one_gadget](https://github.com/david942j/one_gadget) to find gadgets that does a call to execve like `execve('/bin/sh', NULL, NULL)` and write its address into the GOT entry of `__stack_chk_fail` (or other libc function calls) to spawn a shell. Looking at the blog of one_gadget tool [https://david942j.blogspot.com/2017/02/project-one-gadget-in-glibc.html](https://david942j.blogspot.com/2017/02/project-one-gadget-in-glibc.html), it tries to find assembly code blobs that is accessing the string `"/bin/sh"` as well as calling the `execve` function.

The challenge has included the libc file that is being used. We can directly run one_gadget to find possible gadgets and their offsets from libc base address.

![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_15.png)

While the result shows 3 gadgets, only the second one at `0xe3b01` will work in this case. This is because of the constraints listed in the one_gadget output. If we set a breakpoint at when `__stack_chk_fail` is called, we can see the values stored in each register through pwndbg.

![Screenshot](/assets/img/htb-challenges/pwn/r0bob1rd-screenshots/image_16.png)

We can clearly see that while `rdx` and `r15` are 0 (NULL), `rsi` and `r12` contains value that does not match the constraint. Therefore, only the second gadget is usable if we are replacing the entry of `__stack_chk_fail`.

# Final payload
Since we have the offset and the leaked libc base address, we can simply calculate the address of this gadget and perform the same trick to replace the GOT entry to jump to this gadget and get a shell. Here I opt to use the `fmtstr_payload` from pwntools as I was not able to figure out how to break down the large address value into smaller chunks and perform the overwrite action.

The following is the example payload created based on the calculated address. It basically breaks down the address into 3 parts and writes then one by one (from `0x8b01` to `0x3f91` to `7f17`). The first value `35585` is directly equal to `0x0b01`. The second value comes from `35585 + 46224 = 81809` which is `0x13f91`, but it is only writing 2 bytes with the `$hn` specifier, so the most significant bit was ignored. Similarly for the last value `35585 + 46224 + 16262 = 98071` which is `0x17f17` and only writing 2 bytes.

```python
Gadget address: 0x7f173f918b01
Final payload: b'%35585c%13$lln%46224c%14$hn%16262c%15$hn( `\x00\x00\x00\x00\x00* `\x00\x00\x00\x00\x00, `\x00\x00\x00\x00\x00'
```

The final exploit script can be found here: [https://github.com/dexso120/misc_scripts/blob/main/ctf/htb_challenges/very_easy/pwn_r0bob1rd_exploit.py](https://github.com/dexso120/misc_scripts/blob/main/ctf/htb_challenges/very_easy/pwn_r0bob1rd_exploit.py)

# References
## Other Writeups
[https://github-wiki-see.page/m/Pez1181/CTF/wiki/HTB-R0bob1rd-writeup](https://github-wiki-see.page/m/Pez1181/CTF/wiki/HTB-R0bob1rd-writeup)

[https://github.com/jon-brandy/hackthebox/blob/main/Categories/Pwn/r0bob1rd/README.md](https://github.com/jon-brandy/hackthebox/blob/main/Categories/Pwn/r0bob1rd/README.md)


## Useful Videos about Format String
[https://www.youtube.com/watch?v=9SWYvhY5dYw](https://www.youtube.com/watch?v=9SWYvhY5dYw) (by RazviOverflow)

[https://www.youtube.com/watch?v=t1LH9D5cuK4](https://www.youtube.com/watch?v=t1LH9D5cuK4) (by LiveOverflow)

# Tools
[https://github.com/david942j/one_gadget](https://github.com/david942j/one_gadget) (one_gadget)

[https://github.com/pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) (pwndbg)

[https://hex-rays.com/ida-free](https://hex-rays.com/ida-free) (IDA free)

[https://github.com/Gallopsled/pwntools](https://github.com/Gallopsled/pwntools) (pwntools)
