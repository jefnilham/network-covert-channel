from netfilterqueue import NetfilterQueue
import socket
import subprocess
import sys
from IPy import IP as I
from scapy.all import *
from struct import *
import os
from threading import Timer

def cb(payload):
    global ack, size, received, previous, ttl, result, start, x, guide, skip, skipped
    pkt = IP(payload.get_payload())
    if start == True:
        size = (pkt[TCP].ack - ack)
        if guide != size and guide != 0 and size != 0:
            result+='1'            
        elif guide == size and guide != 0 and size != 0 and skip == False:
            result+='0'
            skip = True
            skipped = x
        if len(result) == 17:
            print(result)
            
            if result.endswith('000'):
                print('Do nothing.')
            elif result.endswith('001'):
                print('Operation compromised.')
            elif result.endswith('010'):
                print('We have a mole.')    
            elif result.endswith('011'):
                print('This operation is a bust.')
            elif result.endswith('100'):
                print('Attack now.')
            elif result.endswith('101'):
                print('Attack at noon.')
            elif result.endswith('110'):
                print('Attack at midnight.')
            elif result.endswith('111'):
                print('Attack at dawn.')
                
            result ='Bit received: '
            x = 0
            guide = 0
        if skip == True and (skipped+2) == x:
            skip = False
            skipped = 0
        x+=1
    elif start == False and pkt[TCP].ack != 0 and ack !=0 and ack!=pkt[TCP].ack and guide == 0:
        guide = (pkt[TCP].ack - ack)
    if pkt[IP].ttl == 50 and start == False:
        start = True
    elif pkt[IP].ttl == 50 and start == True:
        start = False
    ack = pkt[TCP].ack
    previous = pkt[IP].ttl
    payload.set_payload(bytes(pkt))
    payload.accept()


ack=0
result = 'Bit received: '
guide = 0
size = 0
x=0
previous = 0
start = False
skip = False
skipped = 0

while True:
    try:
        src_ip = str(I(input('Please enter the source ip address [0 = Exit] : ')))
    except (ValueError) as src_ip:
        print("Your input doesn't appear to be an IPV4 address.")
    else: 
        if src_ip == "0.0.0.0":
            sys.exit()	
        break

subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--source', src_ip, '-j', 'NFQUEUE', '--queue-num', '1'])

print('Creating queue...')
q = NetfilterQueue()
q.bind(1, cb)
print('Finished creating queue!')

try:
    q.run()
except KeyboardInterrupt:
    print("Exiting...")
    subprocess.call(['sudo', 'iptables', '--flush'])
    sys.exit()

try:
    q.unbind()
except RuntimeError:
    print('Exiting...')
    subprocess.call(['sudo','iptables', '--flush'])
q.close()
