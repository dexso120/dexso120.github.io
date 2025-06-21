---
title: HTB Challenge RE BinCrypt Writeup
date: 2025-06-21
categories: [CTF, HTB]
tags: [CTF, HTB, Challenges, RE, Medium]
description: HTB Challenge RE BinCrypt Breaker Writeup
---
# Basic checks
- file information
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_1.png)

# Disassemble "checker"
Looking at the disassembly in Ghidra, the main function seems a bit complicated with quite a lot of parameters. These parameters seems to be mostly used in the "decrypt" function.
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_2.png)

This is the decrypt function. Surprisingly most of the function parameters are not even used in here.
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_3.png)
The decrypt function basically does the following steps.
1. Open "file.bin" (Given by the challenge)
2. Get each character in file.bin and XOR it with the value "0xab"
3. Write the XOR result byte to "." (current directory)

There isn't any other notable actions does by the "checker" binary, so it seems that the real binary to be reversed is in "file.bin". Since it's a simple XOR encryption, a simple python script can be used to decrypt it.
```python
import argparse
import sys

def main():

	parser = argparse.ArgumentParser()
	parser.add_argument('-f','--file', help='File to decrypt', required=True)
	args = parser.parse_args()

	outfile = "decrypted.bin"
	key = b'\xab'
	new_content = b''

	with open(args.file, "rb") as f:
		while (byte := f.read(1)):
			byte = bytes(a ^ b for a, b in zip(byte, key))
			new_content += byte

	with open(outfile, "wb") as o:
		o.write(bytes(new_content))



if __name__ == "__main__":
	main()
```

# Disassemble "decrypted.bin"
The main function prompts for the user to input the flag without the "HTB{}". Then it passes the input to another function (renamed "check_input") and prints 2 different messages based on the return value of the function.
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_4.png)

Following the "check_input" function, the user input goes through multiple operations:
1. Checks if the input string is exactly 28 characters.
2. Swapping multiple characters within the string ("multiple_element_swaps").
3. Splitting the string in half.
4. Checks if each substring is exactly 14 characters.
5. For each substring, pass to a transposition function ("transform_array").
6. Concatenate the 2 substrings.
7. Compare the resulting string to the value `RV{r15]_vcP3o]L_tazmfSTaa3s0`

## Swapping Elements
First looking at the "multiple_element_swaps" function. The function calls another swap function ("swap_elements") multiple times with the input string. The only difference in each call is the 2nd and 3rd parameter.
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_5.png)

The "swap_element" function swaps 2 characters in the 1st parameter (string) with indexes in the 2nd and 3rd parameter.
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_6.png)

Based on this, the "multiple_element_swaps" function has swapped some characters as listed below. 
```
string[0] <=> string [12]
string[14] <=> string[26]
string[4] <=> string[8]
string[20] <=> string[23]
```

## Array Transposition and XOR
Next we'll look at the "transform_array" function. At the start of the function, 2 arrays have been initialized with some values.
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_7.png)

To make it easier for human reading and later decoding operations, the arrays are listed below.
```python
array1 = [9, 12, 2, 10, 4, 1, 6, 3, 8, 5, 7, 11, 0, 13]
array2 = [2, 4, 6, 8, 11, 13]
```

Next, a nested for-loop is used to perform transposition on the input string. In the inner loop, the transposition uses values in array1 as the index to get the characters in the input string and add it to a temporary array. Then the outer loop repeats the same action 8 times (note that i is starting at 1).
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_8.png)

To do an example, lets use a simple string of alphabets as an example, the original string would look like this:
```
abcdefghijklmn
```

The transposition will use the first value in array1 (i.e. array1\[0\]), which is 9, as the index. Then it will get the 9th character in the input string and add it as the first element of the temp_array. This will be repeated for all characters in the string.
```python
temp_array[0] = string[array1[0]]
# which is equal to
temp_array[0] = string[9]
```

After the first round of transforming the array, the output string looks like this:
```
jmckebgdifhlan
```

The process is repeated 8 times in total.

After the transposition, another for-loop is used to iterate through array2. Similar to array1, the array2 stores the index value which will be referenced here. Each of the specified nth element will be XORed with the "byte_value", which is passed as the 2nd parameter of the function.
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_9.png)

And after that, the function simply returns the transformed string. Now we have understand all of the string operations, we can try to decode the flag.
# Decoding Flag
So we are given the encoded flag `RV{r15]_vcP3o]L_tazmfSTaa3s0`. To decode it, we will have to repeat the steps above in reverse, which is:
1. Splitting the string in half.
2. For each substring, perform XOR with the given value and the reverse transposition.
3. Concatenate the 2 substrings.
4. Perform the character swapping.

To perform the reverse of the original transposition, we can simplify the operation by finding the final transposition array to determine how each character was moved. The following script does so by performing the original transposition on a string and lookup the original index of each character.
```python
a = "abcdefghijklmnopqrstuvwxyz12"

string_array = list(a[:14])
temp_array = [0] * 14
array1 = [9, 12, 2, 10, 4, 1, 6, 3, 8, 5, 7, 11, 0, 13]

for i in range(1, 9):
	for j in range(14):
		temp_array[j] = string_array[array1[j]]

	string_array = temp_array
	temp_array = [0] * 14

print(f"Transformed String: {''.join(string_array)}")

temp_array_2 = []

for i in string_array:
	temp_array_2.append(a.index(i))

print(f"Transform array: {temp_array_2}")
```

The script returns the following output:
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_10.png)

And with this array, we can create a function to perform the XOR and the transposition as below. Note that we will call this function with each half of the encoded string.
```python
def transform1(list_text, num_byte):
	# Reversed array1
	array1 = [1, 9, 2, 7, 4, 0, 6, 10, 8, 12, 3, 11, 5, 13]
	array2 = [2, 4, 6, 8, 11, 13]
	
	# XOR with num_byte
	for i in array2:
		list_text[i] = bytes(a ^ b for a, b in zip(list_text[i].encode("utf-8"), num_byte)).decode("utf-8")

	# Reverse Transposition
	temp_text = [''] * len(array1)
	for i in range(len(array1)):
		temp_text[array1[i]] = list_text[i]

	print(f"After transform1: {temp_text}")

	return temp_text
```

Then we will combine the resulting 2 substrings and perform a character swap with the function below.
```python
def transform2(list_text):
	list_text[0], list_text[12] = list_text[12], list_text[0]
	list_text[14], list_text[26] = list_text[26], list_text[14]
	list_text[4], list_text[8] = list_text[8], list_text[4]
	list_text[20], list_text[23] = list_text[23], list_text[20]

	print(f"After transform2: {list_text}")

	return list_text
```

The full script for decoding is included below.
```python
import argparse
import sys

# Flag to decode
# RV{r15]_vcP3o]L_tazmfSTaa3s0

def transform1(list_text, num_byte):
	# Reversed array1
	array1 = [1, 9, 2, 7, 4, 0, 6, 10, 8, 12, 3, 11, 5, 13]
	array2 = [2, 4, 6, 8, 11, 13]
	
	# XOR with num_byte
	for i in array2:
		list_text[i] = bytes(a ^ b for a, b in zip(list_text[i].encode("utf-8"), num_byte)).decode("utf-8")

	# Reverse Transposition
	temp_text = [''] * len(array1)
	for i in range(len(array1)):
		temp_text[array1[i]] = list_text[i]

	print(f"After transform1: {temp_text}")

	return temp_text

def transform2(list_text):
	list_text[0], list_text[12] = list_text[12], list_text[0]
	list_text[14], list_text[26] = list_text[26], list_text[14]
	list_text[4], list_text[8] = list_text[8], list_text[4]
	list_text[20], list_text[23] = list_text[23], list_text[20]

	print(f"After transform2: {list_text}")

	return list_text

def main():

	parser = argparse.ArgumentParser()
	parser.add_argument('-s','--string', help='String to decode', required=True)
	args = parser.parse_args()

	# String: RV{r15]_vcP3o]L_tazmfSTaa3s0

	if (len(args.string) != 28):
		print("[-] String is not 28 in length.")
		sys.exit(1)

	# Split string
	string_first_half = list(args.string[:14])
	string_second_half = list(args.string[14:])

	# Perform XOR and transposition
	string_first_half = transform1(string_first_half, b"\x02")
	string_second_half = transform1(string_second_half, b"\x03")

	full_string = string_first_half + string_second_half

	full_string = transform2(full_string)

	print(f"Flag: {''.join(full_string)}")


if __name__ == "__main__":
	main()
```

With this script, we are able to decode the flag (without the `HTB{}` bit).
![Screenshot](/assets/img/htb-challenges/re/bincrypt_breaker-screenshot/image_11.png)
