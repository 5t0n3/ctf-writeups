import os
import random
import string

charset = string.ascii_letters
pw = (''.join(random.choices(charset, k=4)))
fn = (''.join(random.choices(charset, k=4)))
print(fn,pw)

os.system('zip '+fn+'.zip Nothing.docx -P '+pw)

for _ in range(30):
    fnOLD = fn
    pw = (''.join(random.choices(charset, k=4)))
    fn = (''.join(random.choices(charset, k=4)))
    print(fn,pw)
    os.system('zip '+fn+'.zip '+fnOLD+'.zip -mP '+pw)

fnOLD = fn
pw = (''.join(random.choices(charset, k=4)))
fn = "Safe" 
print(fn,pw)
os.system('zip '+fn+'.zip '+fnOLD+'.zip -mP '+pw)
