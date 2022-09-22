from pwn import *

BIN_DIR = "./bin/"

elf = ELF(BIN_DIR+"vuln1")

p = process(BIN_DIR+"vuln1")
p.sendline(cyclic(30, n=8))
p.wait()

core = p.corefile
print(str(core))


print(cyclic_find(core.read(core.rsp, 8), n=8))