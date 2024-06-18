import socket

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


def btb(num):
    return int.from_bytes(num, byteorder='big')


def make_packet(src, dst, ttl):
    # ip headers
    version_ihl_tos = b'\x45\x00'
    total_len = b'\x00\x1c'
    identification = b'\xab\xcd'
    flags_frag_offset = b'\x00\x00'
    ttl_protocol = ttl + b'\x01'

    ip_header_checksum = 0
    for field in [version_ihl_tos, total_len, identification,
                  flags_frag_offset, ttl_protocol, src[0:2], src[2:4],
                  dst[0:2], dst[2:4]]:
        ip_header_checksum += btb(field)
    try:
        ip_header_checksum = ip_header_checksum.to_bytes(length=2, byteorder='big')
    except Exception:
        ip_header_checksum = ip_header_checksum.to_bytes(length=3, byteorder='big')
        ip_header_checksum = ((btb(ip_header_checksum[1:3]) + btb(ip_header_checksum[0:1]))
                              .to_bytes(length=2, byteorder='big'))

    ip_header_checksum = (btb(b'\xff\xff') - btb(ip_header_checksum)).to_bytes(length=2, byteorder='big')

    ip_header = (version_ihl_tos + total_len + identification + flags_frag_offset + ip_header_checksum +
                 ttl_protocol + ip_header_checksum + src + dst)

    # icmp headers
    type_of_msg_code = b'\x08\x00'
    icmp_checksum = b'\x1a\x35'
    id_seq_number = b'\x12\x34\x00\x01'

    icmp_header = type_of_msg_code + icmp_checksum + id_seq_number
    return ip_header + icmp_header


if __name__ == '__main__':
    pk = make_packet(b'\x0a\x0a\x0a\x02', b'\x08\x08\x08\x08', b'\x40')

