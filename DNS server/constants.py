import socket

RECORD_TYPES = {
    1: 'IPv4',
    2: 'NameServer',
    6: 'StartOfAuthority',
    28: 'AAAA'
}

RECORD_CODES = {
    'IPv4': 1,
    'NameServer': 2,
    'StartOfAuthority': 6,
    'AAAA': 28
}

def domain_to_bytes(domain):
    parts = domain.strip('.').split('.')
    result = b''
    total = 0
    for part in parts:
        length = len(part)
        result += int.to_bytes(length, 1, 'big')
        total += 1
        result += part.encode('utf-8')
        total += length
    result += b'\x00'
    total += 1
    return result, total

def fetch_remote_data(data, remote_ip='8.8.8.8', remote_port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    try:
        sock.sendto(data, (remote_ip, remote_port))
        resp = sock.recvfrom(1024)[0]
        return resp, True
    except socket.timeout:
        print('Remote server not reachable')
        return b'', False
    finally:
        sock.close()
