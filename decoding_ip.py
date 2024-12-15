import struct
import socket
import os
import ipaddress
import sys

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
        """ LOOK AT THIS WIKIPEDIA ENTRY TO UNDERSTAND THE PROTOCOL MAP

        .    https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        .                                                                """