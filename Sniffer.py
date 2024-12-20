
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
''' MORE MODULES IM ABT TO SPAM'''

local_host = '192.168.178.34'

def main():
    if os.name == 'nt': #checking if Windows (Should use this more)
        sock_protcol = socket.IPPROTO_IP
    else:
        sock_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_protcol) #THird Place, we can inesert any Protocol.
    sniffer.bind((local_host, 80)) #Bind to your own adress, listen on all interfaces via port 0

    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name =='nt': 
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) #ACCESS Interface, Turn on PromMode on Win.
     
    
    x = (sniffer.recvfrom(65565))
    print(x.decode('utf-8'))

    if os.name =='nt':
        sniffer.ioctl(socket.SIO_RCVALL , socket.RCVALL_OFF)
    
if __name__ == '__main__':
    main() 