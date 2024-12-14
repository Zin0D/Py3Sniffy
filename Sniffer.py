import socket
import os     #'' """               """ ''
''                    """ d """                          "__--"
""" """""" ECHO                KALI I HEAD OF THE DRAGON K
    S4veTheW0rld.pcap
    ECHO
"""

''' IM GONNA BURN MY HOUSE DOWN AND     
-                                   NEWVER LOOK 
Depolying a Tool that uses Lin and Win              -BACK'''

''' SHELLCODE EXEC INCOMING SOON'''

local_host = '127.0.0.1'

def main():
    if os.name == 'nt': #checking if Windows (Should use this more)
        sock_protcol = socket.IPPROTO_IP
    else:
        sock_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_protcol) #THird Place, we can inesert any Protocol.
    sniffer.bind((local_host, 0))
