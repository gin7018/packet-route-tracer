import socket


def standardize_bytes(b: bytes):
    if len(b) == 2:
        return b
    elif len(b) < 2:
        return b'\x00' + b
    else:
        first_byte = b[:4]
        second_byte = b[4:]
        return first_byte ^ second_byte


def calculate_checksum(b: bytes):
    last4 = bitstring.BitArray(b[-2:])
    first = bytes.fromhex('000' + chr(b[0]))
    rm = last4 ^ first
    ffff = bitstring.BitArray(b'\xff\xff') & ~rm
    return ffff


def make_packet(src_addr: hex, dst_addr: hex, src_port: hex, dst_port: hex, data: str):
    # ip headers
    version_ihl = b'\x45'  # 4 for ipv4 | 5 for ip header segment length
    tos = b'\x00'
    tt_len = b'\x00\x00'
    packet_id = b'\xaa\xaa'  # fragments of this packet will be given this id i think
    ip_flags_offset = b'\x00\x00'  # flags | fragmentation offset
    ttl = b'\x03'
    protocol = b'\x06'  # for tcp
    ip_ck_sum = b'\x00\x00'  # todo to be updated

    tcp_len = b'\x00\x00'
    tcp_len += bytes(sum(len(header) for header in [version_ihl, tos, tt_len, packet_id,
                                                    ip_flags_offset, ttl, protocol, ip_ck_sum]))
    tt_len += tcp_len

    # tcp headers
    sq_num = b'\x00\x00\x00\x00'
    ack_num = b'\x00\x00\x00\x00'
    data_offset_reserved_flags = b'\x50\x02'  # data offset | reserved | tcp flags [SYN]
    window_size = b'\x71\x10'
    tcp_ck_sum = b'\x00\x00'  # todo to be updated
    urgent_pt = b'\x00\x00'
    # data part of the tcp segment
    payload = bytes(data, "utf-8")

    tt_len += bytes(sum(len(header) for header in [src_port, dst_port, sq_num, ack_num,
                                                   data_offset_reserved_flags, window_size,
                                                   tcp_ck_sum, urgent_pt]) + len(payload))
    # calculating tcp check sum
    tcp_ck_sum += sum(standardize_bytes(header) for header in [protocol, src_addr, dst_addr, tcp_len,
                                                               src_port, dst_port, sq_num, ack_num,
                                                               data_offset_reserved_flags, window_size])
    if len(tcp_ck_sum) != 2:
        tcp_ck_sum = calculate_checksum(tcp_ck_sum)

    # calculating ip check sum
    ip_ck_sum += sum(standardize_bytes(header) for header in [version_ihl, tos, tt_len, packet_id,
                                                              ip_flags_offset, ttl, protocol, src_addr,
                                                              dst_addr])
    if len(ip_ck_sum) != 2:
        ip_ck_sum = calculate_checksum(ip_ck_sum)

    packet = (version_ihl + tos + tt_len +
              packet_id + ip_flags_offset +
              ttl + protocol + ip_ck_sum +
              src_addr +
              dst_addr +
              src_port + dst_port +
              sq_num +
              ack_num +
              data_offset_reserved_flags + window_size +
              tcp_ck_sum + urgent_pt +
              payload)
    print(packet)
    return packet


import bitstring


def main():
    src_addr = 0x7f000001
    src_port = 0x2233
    dst_port = 0x1388
    packet = make_packet(src_addr=src_addr,
                         dst_addr=src_addr,
                         src_port=src_port,
                         dst_port=dst_port,
                         data='hi')

    simple_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    simple_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    simple_socket.sendto(packet, ('127.0.0.1', 0))


if __name__ == '__main__':
    main()
    # data = "hi"
    # payload = bytes(data, "utf-8")
    # print(data, payload)
