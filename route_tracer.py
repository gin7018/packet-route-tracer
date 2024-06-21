import time

import packet_sender

if __name__ == '__main__':
    ttl = 1
    destination = '8.8.8.8'
    reached_destination = False

    while ttl <= 10:
        packet_sender.send_packet(ttl)
        time.sleep(5)

        with open('captured_packets.txt', 'r') as f:
            last_in_bound_packet = f.readlines()[-1].split('---')
            src_ip = last_in_bound_packet[0]
            print(ttl, src_ip)
            if src_ip == destination:
                reached_destination = True
        open('captured_packets.txt', 'w').close()

        if reached_destination:
            break

        time.sleep(10)
        ttl += 1



