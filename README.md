# BOF Tools

This project's goal is to automate many steps in pwn challenges.

The user only have to give the executable and a func that can trigger an overflow.  
Then the user can specify the attack type he want !

## Progress
- [x] Auto find offset

- [x] ret2stack 32 bits
- [x] ret2stack 64 bits

- [x] ret2libc 32 bits
- [ ] ret2libc 64 bits

- [ ] libc leak (ret2plt)
- [ ] ret2libc with aslr
- [ ] ROP chain

## Examples
Some examples can be found in the examples directory