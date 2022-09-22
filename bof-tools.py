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

    def __str__(self):
        return "Type:"+str(self.elf)
    
    def find_offset(self):
        
        p = process(self.elf)

        self.send_func(p,cyclic(30,n=8))
        p.wait()

        core = p.corefile

        return cyclic_find(core.read(core.esp, 8), n=8)
    
    def find_stack_addr(self, offset):
        
        p = process(self.elf)

        payload = b'A' * (offset + 4)

        self.send_func(p,payload)
        p.wait()

        core = p.corefile

        return core.esp
    
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
        print(exp)
        offset = (exp.find_offset())

        print(offset)

        print(f"{exp.find_stack_addr(offset)}:x")



if __name__=="__main__":
    test_local()