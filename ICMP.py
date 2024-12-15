import struct
import os
import ipaddress
import socket
import sys



class icmp:
    def __init__(self, buff):
        packet = struct.unpack("<BBHHH",buff) 
        self.type = packet[0]
        self.code = packet[1]
        self.chksum = packet[2]
        self.id = packet[3]
        self.seqnum = packet[4]

        self.type_map = {3: "DESTINATION UNREACHABLE", 8: "ECHO REPLY"}