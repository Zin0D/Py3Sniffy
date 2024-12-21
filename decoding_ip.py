import struct
import socket
import os
import ipaddress
import sys

import ICMP

""" https://docs.python.org/3/library/struct.html" #doc of Struct libary.
    https://www.elektronik-kompendium.de/sites/net/2011241.htm Website vor the IPV4 header.
    
    WE NEED TO APPLY SOME BIT MANIPULTION IN ORDER TO EXTRACT THE DATA WITH THIS LIBARY.

"""


""" BIT AND GATE Operations 101

    1111 1001 1101 0101 

    AND OPERATION ADDITION:

    0001 1111 1111 1111

    =

    0001 1001 1101 0101
"""

class IPV4_HEADER:

    """ PACKET CONSTRUCTOR FOR THE IPV4 HEADER """
    def __init__(self, buff=None): 

        ipv4_header = struct.unpack('<BBHHHBBH4s4s',buff) #Check Documentation on how to Package the binary data.
        self.vrsion = ipv4_header[0] >> 4
        self.ihl = ipv4_header[0] & 0xF 
        self.tos = ipv4_header[1]
        self.lnght = ipv4_header[2]
        self.id = ipv4_header[3]
        self.frgm_order = ipv4_header[4] >> 13 
        self.offset = ipv4_header[4] & 0x1FFF
        
        self.ttl = ipv4_header[5]
        self.protocol = ipv4_header[6]
        self.chcksum = ipv4_header[7]
        self.src = ipv4_header[8]
        self.dst = ipv4_header[9]
    
        self.src_adress = ipaddress.ip_address(self.src)
        self.dst_adress = ipaddress.ip_address(self.dst)

        #Mapping protocols
        self.protocol_map = {1: "ICMP" , 6: "TCP", 17: "UDP"} 
        """ LOOK AT THIS WIKIPEDIA ENTRY TO UNDERSTAND THE PROTOCOL MAP VALUES

        .    https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        .                                                                """
        try:
            self.protocol = self.protocol_map[self.protocol] 
        except Exception as e:
            print("Protocol Not Found in Specified List")
            self.protocol = str(self.protocol)


def sniffit(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP 
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol) #Sniff only for the specified thing
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL ,socket.RCVALL_ON)

    try:
        while True:
            raw_packet = sniffer.recvfrom(65535)[0] #We only want the Payload since we allready have our SRC Adress ;)#
            header_info_ipv4 = IPV4_HEADER(raw_packet[0:20]) #NOW THE FUN BEGINNS
            print(f'Protocol: {header_info_ipv4.protocol}, from: [{header_info_ipv4.src_adress}] --> [{header_info_ipv4.dst_adress}] : TTL {header_info_ipv4.ttl}')
            if header_info_ipv4.protocol == "ICMP":
                offset = header_info_ipv4.ihl * 4 #IHL can be range from 5 - 16 (IN WHICH 16-1 is the end.)
                buf = raw_packet[offset:offset + 8]
                icmp_header = ICMP.ICMP(buf) #ICMP file and ICMP Class, rip for readability.
                print(f"Icmp Type: {icmp_header.type}")
            
                
    except KeyboardInterrupt:
        print("EXITING....")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit() #Clean Exit with Swaggy :D

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.178.34' #ENTER IN YOUR OWN HOST.
    sniffit(host)