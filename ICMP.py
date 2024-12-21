import struct
import os
import ipaddress
import socket
import sys

""" THIS CLASS IS IMPLEMENTED BY IMPORTING IT INTO decoding_ip.py 
    I JUST LIKE HAVING ALL SEPERATE CLASSES SO DONT WONDER! :D
"""

class ICMP:
    def __init__(self, buff):
        packet = struct.unpack("<BBHHH",buff) 
        self.type = packet[0]
        self.code = packet[1]
        self.chksum = packet[2]
        self.id = packet[3]
        self.seqnum = packet[4]

        self.type_map = {0:"ECHO REPLY",3: "DESTINATION UNREACHABLE", 8: "ECHO REQUEST"}
        try:
            self.type = self.type_map[self.type]
        except KeyError as kms:
            print("TYPE NOT FOUND")