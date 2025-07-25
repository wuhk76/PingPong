# PingPong
Wireless monitor mode chat

## What is PingPong?

PingPong is an experimental, wireless, point-to-point chatting program written in Python for Linux operating systems. Unlike conventional chatting programs, PingPong directly sends
Wi-Fi packets from device to device, without the need of a router. It accomplishes this by using the packet injection ability of certain wireless cards in monitor mode. For instance, this can be 	advantageous with nearby neighbors, a public place that requires Wi-Fi payment, or a school or office that has severe internet restrictions.

## Setting Up

To set PingPong, the file (pingpong.py) must be downloaded and placed in an appropriate folder. A wireless card that supports monitor mode and packet injection must be installed to the
system. Python libraries Scapy, Cryptography, Subprocess, Base64, Time, and OS must also be installed. It is also important to note that because packet transmission his a hardware specific 
task, the Python program may have to run with administrator privileges. When started, the program will ask for the MAC address of the monitor mode interface that it will chat with, along with
the interface name of the current wireless card that is in monitor mode, for example (wlan0mon). The program might also ask for a Fernet encryption key, but it can be left blank. However, 
by leaving it blank, the packets can have publicly visible messages. When chatting, a user can directly input a message to the desired host, but the program will wait afterwords for the host
to respond before the user to chat again. This is a common bug that is still in the process of fixing. However, there are special commands the user can input when chatting that can allow 
certain functions of the program.

## Commands (always start with “:” or “^”)

### Receive: “:r” (no options)
	
Puts the interface in receiving mode, and it will scan until a message of non-zero length is sent. If both users input “:r” at the same time, one will revert to sending mode.

### Send “:s” {message}

Sends a message from the current interface to the receiving interface. Unlike natural chat, the program will not go to receiving mode afterwords. 

### Recursive Receive: “:rr” (no options)

Puts interface into a receiving loop, where it can only receive messages the whole time. 

### Recursive Send: “:rs” (no options)

Puts the interface in constant sending mode, where it only sends messages.

### File Receive:  “:fr” (no options)

Allows for reception of a file (still experimental). The file will be sent to the directory of the Python program.

### File Send: “:fs” {/path/to/file}

This is an experimental feature that sends a file to the receiving computer. Due to limitations of Wi-Fi packets, it can only send files of a certain size. The maximum possible size 
is around 2.2-2.3 kb, but it can be much smaller due to certain encodings.

### Change Recipient: “:cr” {new destination address}

This changes to a different address that is entered.

### Change Key: “:ck” {new key}

This changes to a new key.

### Quit: “^C” or “:q”

To quit, control C is the most reliable way to exit the program. Command “:q” can sometimes work, but only in some text fields. It cannot work when the program is receiving.
