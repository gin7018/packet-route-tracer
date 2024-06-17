import socket

from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP


def send_packet():
    data = "hi please work"
    ip = IP(dst="google.com")
    icmp = ICMP(type=8)
    rs = sr1(ip/icmp)
    print(rs)


def send_packet_raw_socket():
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.sendto(bytes("hi this is a socker", "utf-8"), ('localhost', 8080))
    print("sent")


if __name__ == '__main__':
    send_packet()
    # send_packet_raw_socket()

