import socket

import pyshark


def icmp_packet_handler(packet):
    ip_layer = packet.ip
    out_bound = socket.gethostbyname(socket.gethostname()) == ip_layer.src
    if out_bound:
        return

    print(f"ICMP packet: {ip_layer.src} -> {ip_layer.dst}")
    with open('captured_packets.txt', 'a') as f:
        f.writelines(f"{ip_layer.src}---{ip_layer.dst}")


def init_live_capture():
    print('starting to sniff...')
    open('captured_packets.txt', 'w').close()  # clean up the file for a new session
    capture = pyshark.LiveCapture(interface='wi-fi', bpf_filter='icmp')
    capture.apply_on_packets(callback=icmp_packet_handler)


if __name__ == '__main__':
    init_live_capture()
