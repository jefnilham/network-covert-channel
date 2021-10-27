from netfilterqueue import NetfilterQueue
import socket
import subprocess
import sys
from IPy import IP as I
from scapy.all import *
from struct import *
import os

def cb(payload):
    global x, reorder, modified_pkt, first, second, reorderStr, firstReorder, secondReorder, thirdReorder, third, fourth, fifth, sixth
    pkt = IP(payload.get_payload())
    if pkt[TCP].flags != 'S' and x < 20 and thirdReorder == False:
        if reorderStr[0:1] == '1' and firstReorder == False:
            if x == (first - 1):
                print('Processing first and second packet....1')
                pkt = IP(payload.get_payload())
                pkt.ttl = 50
                del pkt.chksum
                payload.set_payload(bytes(pkt))
                x+=1
                payload.accept()
            elif x == first:
                print('Capturing first packet..')
                modified_pkt = IP(dst=pkt[IP].dst, src=pkt[IP].src, len=pkt[IP].len,ttl=63)/TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq, ack=pkt[TCP].ack, flags=16)
                payload.drop()
                x+=1
            elif x == second:
                pkt2 = IP(payload.get_payload())
                pkt2.ttl = 65
                del pkt2.chksum
                print('Sending second packet first..')
                payload.set_payload(bytes(pkt2))
                payload.accept()
                print('Sending first next...')
                send(modified_pkt)
                firstReorder = True
                x+=1
            else:
                x+=1
                payload.accept()
        elif reorderStr[0:1] == '0' and firstReorder == False:
            if x == (first - 1):
                print('Processing first and second packet....0')
                pkt = IP(payload.get_payload())
                pkt.ttl = 50
                del pkt.chksum
                payload.set_payload(bytes(pkt))
                x+=1
                payload.accept()
            elif x == first or x == second:
                print('Processing first and second packet....0')
                pkt = IP(payload.get_payload())
                if x == first:
                    pkt.ttl = 63
                elif x == second:
                    pkt.ttl = 65
                    firstReorder = True
                payload.set_payload(bytes(pkt))
                payload.accept()
                x+=1
            else:
                x+=1
                payload.accept()
        elif reorderStr[1:2] == '1' and secondReorder == False and firstReorder == True:
            print('Processing third and fourth packet....1')
            if x == third:
                print('Capturing third packet..')
                modified_pkt = IP(dst=pkt[IP].dst, src=pkt[IP].src, len=pkt[IP].len,ttl=63)/TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq, ack=pkt[TCP].ack, flags=16)
                payload.drop()
                x+=1
            elif x == fourth:
                pkt2 = IP(payload.get_payload())
                pkt2.ttl = 65
                del pkt2.chksum
                print('Sending fourth packet first..')
                payload.set_payload(bytes(pkt2))
                payload.accept()
                print('Sending third next...')
                send(modified_pkt)
                secondReorder = True
                x+=1
            else:
                x+=1
                payload.accept()
        elif reorderStr[1:2] == '0' and secondReorder == False and firstReorder == True:
            print('Processing third and fourth packet....0')
            pkt = IP(payload.get_payload())
            if x == third:
                pkt.ttl = 63
            elif x == fourth:
                pkt.ttl = 65
                secondReorder = True
            payload.set_payload(bytes(pkt))
            payload.accept()
            x+=1
        elif reorderStr[2:3] == '1' and thirdReorder == False and secondReorder == True and firstReorder == True:
            print('Processing fifth and sixth packet....1')
            if x == fifth:
                print('Capturing fifth packet..')
                modified_pkt = IP(dst=pkt[IP].dst, src=pkt[IP].src, len=pkt[IP].len,ttl=63)/TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq, ack=pkt[TCP].ack, flags=16)
                payload.drop()
                x+=1
            elif x == sixth:
                pkt2 = IP(payload.get_payload())
                pkt2.ttl = 65
                del pkt2.chksum
                print('Sending sixth packet first..')
                payload.set_payload(bytes(pkt2))
                payload.accept()
                print('Sending fifth next...')
                send(modified_pkt)
                x+=1
            elif x == (sixth + 1):
                pkt = IP(payload.get_payload())
                pkt.ttl = 50
                del pkt.chksum
                payload.set_payload(bytes(pkt))
                payload.accept()
                thirdReorder = True
                x+=1
            else:
                x+=1
                payload.accept()
        elif reorderStr[2:3] == '0' and thirdReorder == False and secondReorder == True and firstReorder == True:
            print('Processing fifth and sixth packet....0')
            if x == (sixth + 1):
                pkt = IP(payload.get_payload())
                pkt.ttl = 50
                del pkt.chksum
                payload.set_payload(bytes(pkt))
                payload.accept()
                thirdReorder = True
            else:
                pkt = IP(payload.get_payload())
                if x == fifth:
                    pkt.ttl = 63
                elif x == sixth:
                    pkt.ttl = 65
                payload.set_payload(bytes(pkt))
                payload.accept()
            x+=1
    elif pkt[TCP].flags == 'S':
        first = 6
        second = first + 1
        third = second + 1
        fourth = third + 1
        fifth = fourth + 1
        sixth = fifth + 1
        print('First: ', first)
        print('Second: ', second)
        x+=1
        payload.accept()
    else:
        x+=1
        payload.accept()
    if x == 14:
        subprocess.call(['sudo', 'iptables', '--flush'])

x = 1
reorder = 0
firstReorder = False
secondReorder = False
thirdReorder = False

while True:
    try:
        dest_ip = str(I(input('Please enter the destination ip address [0 = Exit] : ')))
    except (ValueError) as dest_ip:
        print("Your input doesn't appear to be an IPV4 address.")
    else: 
        if dest_ip == "0.0.0.0":
            sys.exit()	
        print(dest_ip)
        break

subprocess.call(['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--destination', dest_ip, '-j', 'NFQUEUE', '--queue-num', '1'])

print('Creating queue...')
q = NetfilterQueue()
q.bind(1,cb)
print('Finished creating queue!')

while True:
    try:
        reorder = int(input('3 bits you want to convey [Eg. 101 or 110][6 = Exit]: '))
    except (ValueError, SyntaxError, NameError):
        print("Your input doesn't appear to be an integer.")
    else:
        if str(reorder) == '6':
            print('Exiting...')
            subprocess.call(['sudo', 'iptables', '--flush'])
            sys.exit()
        elif str(reorder) == '100' or str(reorder) == '101' or str(reorder) == '110' or str(reorder) == '111' or str(reorder) == '0' or str(reorder) == '10' or str(reorder) == '11' or str(reorder) == '1' or str(reorder) == '8' or str(reorder) == '9':
            if str(reorder) == '1' or str(reorder) == '0':
                reorderStr = '00' + str(reorder)
                print(reorderStr)
            elif str(reorder) == '10' or str(reorder) == '11':
                reorderStr = '0' + str(reorder)
                print(reorderStr)
            elif str(reorder) == '8':
                reorderStr = '010'
                print(reorderStr)
            elif str(reorder) == '9':
                reorderStr = '011'
                print(reorderStr)
            else:
                reorderStr = str(reorder)
            break
        else:
            print("Invalid number. ")

try:
    q.run()
except KeyboardInterrupt:
    print("Exiting...")
    subprocess.call(['sudo', 'iptables', '--flush'])
    sys.exit()

q.unbind()