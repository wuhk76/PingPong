import os
import time
import base64
import subprocess
from scapy.all import *
from cryptography.fernet import Fernet as fernet

class PingPong:

    def __init__(self):
        self.dest = ''
        self.iface = []
        self.key = ''

    def send(self, message):

        try:
            message = message.encode('utf-8')

        except:
            message = message

        if self.key != '':
            cipher = fernet(self.key)
            message = base64.b64encode(message)
            message = cipher.encrypt(message)

        else:
            message = base64.b64encode(message)

        packet = RadioTap() / Dot11(type = 2, subtype = 0, addr1 = self.dest, addr2 = self.iface[1], addr3 = self.iface[1]) / LLC() / SNAP() / Raw(load = message)
        sendp(packet, iface = self.iface[0], verbose = False)

    def receive(self):
        rmessage = ''

        while len(rmessage) < 1:
            packet = sniff(iface = self.iface[0], count = 1)
            packet = packet[0]

            if packet.haslayer(Raw) and packet.haslayer(Dot11) and packet.addr1 == self.iface[1]:
                rmessage = packet[Raw]

        rmessage = rmessage.load

        if self.key != '':
            cipher = fernet(self.key)
            rmessage = cipher.decrypt(rmessage)
            rmessage = base64.b64decode(rmessage)

        else:
            rmessage = base64.b64decode(rmessage)

        try:
            rmessage = rmessage.decode('utf-8')

        except:
            rmessage = rmessage

        return rmessage

    def dialup(self, dest, iface, key):
        subprocess.run(f'ip link set dev {iface} mtu 2304', shell = True)
        term = subprocess.run(f'ip link show {iface}', capture_output = True, text = True, shell = True)
        term = term.stdout.split('radiotap')
        term = term[1]
        term = term.split('brd')
        term = term[0]

        self.dest = dest
        self.iface = [iface, term.strip()]
        self.key = key.encode() if len(key) == 44 else ''
        encrypted = 'encrypted' if len(self.key) == 44 else ''

        print(f'Connected to {self.dest} on interface {self.iface[0]} {encrypted}')

pingpong = PingPong()
pingpong.dialup(input('Enter destination MAC address: '), input('Enter interface name: '), input('Enter encryption key (leave blank for no encryption): '))
print('')
command = ''
running = True

while running:
    message = input('(you):')

    if message == ':q':
        pingpong.send(' ')
        running = False
        break

    elif message == ':r':
        pingpong.send(' ')
        print(f'({pingpong.dest}):{pingpong.receive()}')

    elif message[0:2] == ':s':
        info = message.split(' ')
        del info[0]
        info = ' '.join(info)
        pingpong.send(info)

    elif message == ':rr':

        while running:
            pingpong.send(' ')
            print(f'({pingpong.dest}):{pingpong.receive()}')
            time.sleep(1)

    elif message == ':rs':

        while running:
            rsinput = input('(you)rs:')

            if rsinput == ':q':
                break

            else:
                pingpong.send(rsinput)
                time.sleep(1)

    elif message == ':fr':
        pingpong.send(' ')
        rpath = os.path.dirname(__file__)
        rname = pingpong.receive()
        time.sleep(2)
        rdata = pingpong.receive()

        if type(rdata) == str:
            rdata = rdata.encode('utf-8')

        with open(f'{rpath}/{rname}', 'xb') as rfile:
            rfile.write(rdata)

        print(f'({pingpong.dest}):{rname}')

    elif message[0:3] == ':fs':
        tpath = message.split(' ')
        tpath = tpath[1]
        tname = tpath.split('/')
        tname = tname[-1]

        with open(f'{tpath}', 'rb') as tfile:
            tdata = tfile.read()

        pingpong.send(tname)
        time.sleep(2)
        pingpong.send(tdata)

    elif message[0:3] == ':cr':
        newdest = message.split(' ')
        newdest = newdest[1]
        pingpong.dialup(newdest, pingpong.iface[0], pingpong.key)

    elif message[0:3] == ':ck':
        newkey = message.split(' ')
        newkey = newkey[1]
        pingpong.dialup(pingpong.dest, pingpong.iface[0], newkey)

    else:
        pingpong.send(message)
        print(f'({pingpong.dest}):{pingpong.receive()}')