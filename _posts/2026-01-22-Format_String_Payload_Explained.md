---
title: Format String Payload Explained
date: 2026-01-22
categories: [Notes, Exploit Development]
tags: [Exploit Development, Format String, Notes]
description: Explaining different paylaod format of Format String Exploitation
---
# Description
On my journey of learning exploit development, I found the concept of format string quite complicated. Mostly on crafting a write primitive payload to overwrite bytes in memory. Looking at CTF writeups and tutorials, I always seem to find payloads that are in slightly different format. A lot of CTF writeups simply use the `pwntools` python library to generate the format string payload without much explanation of how the payload works exactly. Therefore, this blog is more of me trying to explain the differences between each payload types to myself and hopefully help others who are as confused as me.
# Format String Specifiers Used
These are the main format specifiers used.

| Specifier | Description|
| --------- | ---------------------------------------------------- |
| `%x`      | Printing values in 4 byte hexadecimal format         |
| `%c`      | Printing values in 1 bytes character format          |
| `%n`      | Write number of bytes printed so far into address    |
| `%hn`     | Same as `%n`, but writes as `short` (2 bytes)        |
| `%hhn`    | Same as `%n`, but writes as `unsigned char` (1 byte) |
| `%ln`     | Same as `%n`, but writes as `long` (4 bytes)         |
| `%lln`    | Same as `%n`, but writes as `long long` (8 bytes)    |

# Example
Let's assume that we can access our own payload on the stack with an offset of 8.

(i.e. the 8th `%x` in the payload below will print `0x41414141` which is the first 4 bytes of the payload itself)
```
AAAA.%x.%x.%x.%x.%x.%x.%x.%x
```

## Payload Format 1
So assuming we want to write to the address `0x11223344`, we will have a payload format as below.
```python
\x44\x33\x22\x11%8$n
```

To break down the payload:
- `\x44\x33\x22\x11` is the target address that we are writing to (in little endian format)
- `%n` will write the number of bytes printed so far to the address
- `8$` simply goes to the 8th position on the stack
	- So we don't need to print out the irrelevant values in between

As 4 bytes were printed out (`\x44\x33\x22\x11`), this means that we will be writing the value `0x4` to the address `0x11223344`.

If we want to specify what value to write to `0x11223344`, we can use `%x` specifier and a `width` value to essentially pad a number of bytes before `%n` to control the number of bytes printed without affecting the offset.

For example, assume we want to write the value `0x400c0f`. We'll first need to convert `0x400c0f` into decimal value(i.e. `4197391`). Then, since we printed 4 bytes before the `%x` specifier, we'll only need to pad `4197391 - 4 = 4197387` bytes. The updated payload is shown below.
```python
\x44\x33\x22\x11%4197387x%8$n
```

So this means we have a general format like this:
```python
<address>%[padding]x%<offset>$n
```
- `address`: target address to write to
- `padding = <target_value> - <address_length>`
- `offset`: the nth argument on the stack where the `address` is stored
## Payload Format 2
From my previous blog, I have encountered issues with the payload format mentioned above. In a 64-bit environment, the full address is actually padded with leading `\x00` NULL bytes (since the address should be 64 bits long) . So technically the payload will become like this:
```python
\x44\x33\x22\x11\x00\x00\x00\x00%4197383x%8$n
```
- Note: padding is adjusted for the NULL bytes

However, as we are sending the payload as a string, functions like `printf` will treat strings as NULL terminated. Therefore, the function will treat the payload above as a string like `\x44\x33\x22\x11\x00` and discards the remaining part of it. This will cause the write attempt to fail as it never hits the format specifiers at the end of the payload.

To my surprise, the payload can be simply fixed by moving the target address after the `%n` specifier. Afterall, printing the address value doesn't matter as we are using it as a reference to the memory anyway. So something like this will still do the trick
```python
%4197383x%8$n\x44\x33\x22\x11\x00\x00\x00\x00
```

But of course we'll need to adjust the specifier. Since we printed 0 characters before `%x`, we can simply use the intended value `4197391` (`0x400c0f`) as the width for `%x`. As for the offset, we'll need to do a bit more calculation. In 64-bit, the stack address increments after 8 bytes (64 bits), so we will have to adjust the string such that the target address `\x44\x33\x22\x11` is aligned on the stack. Before the address value, a total of 13 characters (aka 13 bytes) was stored on the stack. As the stack address increments every 8 bytes, we'll need to ensure that the number of bytes before the address is a multiple of 8 bytes.

If we try using different offsets:
- offset 8: we will be accessing the value `%4197383`
- offset 9: we will be accessing the value `x%8$n\x44\x33\x22`
- offset 10: we will be accessing the value `\x11\x00\x00\x00\x00`

From the offsets above, we cannot properly reference the address `\x44\x33\x22\x11\x00\x00\x00\x00`. So we'll need to add some characters as padding after `%n` to align the stack properly. Here we will start adding characters to make the values `\x44\x33\x22\x11` start at offset 10. As `\x44\x33\x22` is at offset 9, theoretically we should pad 3 characters after `%n` (aka `...$nAAA\x44\x33...`). However, since we will be using offset 10, the number `10` already added 1 additional character to the string, so we will only need 2 characters here.
```python
%4197391x%10$nAA\x28\x20\x60\x00\x00\x00\x00\x00
```

If we try different offsets again:
- offset 8: we will be accessing the value `%4197383`
- offset 9: we will be accessing the value `x%10$nAA`
- offset 10: we will be accessing the value `\x44\x33\x22\x11\x00\x00\x00\x00`

Now we have fixed the payload using a different format and not worry about null bytes in the address.
```python
%[padding]x%<offset>$n[padding2]<address>
```
- `padding`: the value we want to write
- `offset`: offset to accessing the `address` value on stack
- `padding2`: padding characters to align the stack
	- the number of characters before `<address>` should be a multiple of 8
- `address`: target address to write to
## Payload Format 3
While the payload format above works, it quickly becomes inefficient when the value that we want to write is significantly large. For example, if you are trying to write `0x7f173f918b01` to the address, which is `139,737,827,478,273` in decimal value, it will take a long time for the application to print `139,737,827,478,273` characters before hitting the `%n`specifier. Sometimes the application might even timeout or crash.

So instead of writing the whole value of `0x7f173f918b01`, we can actually break it down into different segments and write each segments separately. First, we'll break the value into 2 byte (4 bit) chunks. So we will be writing `0x7f17`, `0x3f91`, `0x8b01` in reverse order (since it's little endian).

First we'll be writing `0x8b01`. The equivalent decimal value is `35585`, so we can use directly as the width. We'll use `%c` to print that many characters (or bytes). Since we don't know what the offset will be at the moment, we'll just use `ZZ` as a placeholder. In theory, we can just simply use `%n` to write the first segment as this is the first write operation. Using `%lln` seems to ensure that the address is initialized without unwanted data (as `lln` will treat the value as 8 bytes long).

Lets say we are writing a value of 0x4141. The difference of using:
- `%hn` -> 0x4141
- `%n` -> 0x00004141
- `%lln` -> 0x0000000000004141

That means if there is any data in the higher bytes of the address, `%lln` will overwrite those with 0s, while `%n` or `%hn` will preserve those bytes and might cause unexpected results.

So back to the payload, we have our initial write below.
```python
%35585c%ZZ$lln
```

Then we shall write `0x3f91` (`16273`) to address + 1 (as we've written 2 bytes earlier). But instead of directly using `16273` as the width, we need to understand that we've previously printed `35585` characters for the first write operation. Luckily, since we are only going to write 2 bytes, we can actually overflow the value so that the most significant byte is ignored. That means we should aim for the value `0x13f91` (`81809`). Since we already printed `35585` characters, will need to print an additional of `81809 - 35585 = 46224` characters. As we don't know the offset yet, we'll put another placeholder `YY` for it. Lastly, we will use the `%hn` specifier to only write 2 bytes.
```python
%35585c%ZZ$lln%46224c%YY$hn
```

Lastly, we can just simply repeat the previous step and calculate the required width needed. At this point we've printed `35585 + 46224 = 81809` (`0x13f91`). To get the value `0x7f17`, we can simply add up the characters until `0x17f17` (`98071`) characters has been printed before the last specifier. So the required width will be `98071 - 81809 = 16262`.
```python
%35585c%ZZ$lln%46224c%YY$hn%16262c%XX$hn
```

After getting the required specifiers, we'll need to determine if the string needs to be padded. The payload above contains exactly 40 characters, which is a multiple of 8. That means that it's already aligned with the stack, and we should be able to reference the first address with offset `8 + 5 = 13`. So the first offset should be `13` and the first address will be the target address we are writing to. To access the higher bytes, we'll simply increment the address by 2 to point to the higher bytes and simple increment the offset to reference it.
```python
%35585c%13$lln%46224c%YY$hn%16262c%XX$hn<address+0>

%35585c%13$lln%46224c%14$hn%16262c%XX$hn<address+0><address+2>

%35585c%13$lln%46224c%14$hn%16262c%15$hn<address+0><address+2><address+4>
```

So from this example, we can have a basic format shown below. Assuming that we break down the hexadecimal value into 2-byte chunks.
- Starting with the least significant 2 bytes
```python
%<width>%<offset>$lln...
```
- For the remaining bytes to write
```python
%<width_n>%<offset_n>$hn...
```

# Conclusion
For the payload formats listed in this blog, format 3 is actually what the payload looks like when using the `pwntools` library to generate a payload. While it's easy to use `pwntools` to craft payloads, I hope that this blog explains a little bit more on how a format string payload can have different formats that still achieves the same result.