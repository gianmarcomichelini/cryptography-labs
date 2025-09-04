from pwnlib.tubes.process import *

program_path = '/Exercises/basics/servers/server-1/server-pwntools.py'

p = process(['python3', program_path, 'Hello!'])

p.readuntil(b"This is the encrypted string:\n")
second_line = p.recv().decode('utf-8').strip()


print(f"Program Output: {second_line}")