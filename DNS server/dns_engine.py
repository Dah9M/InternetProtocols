from constants import *
from dns_request import DNSRequest
from dns_record import DNSRecord
from dns_storage import DNSCacheStorage

class DNSParser:
    def __init__(self, packet: bytes, storage: DNSCacheStorage):
        self.packet = packet
        self.cache = storage
        self.tx_id = packet[:2]
        self.flags = packet[2:4]
        self.num_q = int.from_bytes(packet[4:6], 'big')
        self.num_ans = int.from_bytes(packet[6:8], 'big')
        self.num_auth = int.from_bytes(packet[8:10], 'big')
        self.num_add = int.from_bytes(packet[10:12], 'big')

        self.offset, self.request = extract_request(packet)
        self.records = []
        self.auth_records = []
        self.add_records = []

        if self.num_ans != 0:
            for _ in range(self.num_ans):
                self.offset, rec = extract_record(self.offset, packet)
                self.records.append(rec)
                self.cache.store(rec.domain, rec, rec.rec_type, self.flags)
        if self.num_auth != 0:
            for _ in range(self.num_auth):
                self.offset, rec = extract_record(self.offset, packet)
                self.auth_records.append(rec)
                self.cache.store(rec.domain, rec, rec.rec_type, self.flags)
        if self.num_add != 0:
            for _ in range(self.num_add):
                self.offset, rec = extract_record(self.offset, packet)
                self.add_records.append(rec)
                self.cache.store(rec.domain, rec, rec.rec_type, self.flags)

    def build_response(self, req: DNSRequest) -> bytes:
        answers_blob = b''
        num_answers = 0
        num_auth = 0
        num_add = 0
        response_flags = b'\x85\x80'

        cached = self.cache.lookup(req.name, req.type)
        if cached:
            num_answers = len(cached)
            for rec in cached:
                answers_blob += rec.record_bytes

        header = self.tx_id + response_flags + b'\x00\x01'
        header += int.to_bytes(num_answers, 2, 'big')
        header += int.to_bytes(num_auth, 2, 'big')
        header += int.to_bytes(num_add, 2, 'big')

        return header + req.raw_data + answers_blob

    def __str__(self):
        s = f"{self.tx_id} {self.flags} {self.num_q} {self.num_ans} {self.num_auth} {self.num_add}\n"
        s += str(self.request) + "\n"
        for rec in self.records:
            s += str(rec) + "\n"
        return s

def parse_name(pos: int, data: bytes, nested: bool = False):
    name_parts = []
    jumped = False

    while True:
        if pos >= len(data):
            break

        length = data[pos]

        if length == 0:
            pos += 1
            break

        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                break

            pointer = int.from_bytes(data[pos:pos+2], 'big') & 0x3FFF
            pointed_pos, pointed_name = parse_name(pointer, data, True)
            name_parts.append(pointed_name)
            pos += 2
            jumped = True
            break
        else:
            if pos + 1 + length > len(data):
                break
            segment = data[pos+1: pos+1+length].decode('utf-8', errors='replace')
            name_parts.append(segment)
            pos += 1 + length

    if not jumped:
        new_pos = pos
    else:
        new_pos = pos

    name = '.'.join(part for part in name_parts if part)
    return new_pos, name

def extract_request(data: bytes):
    pos, domain = parse_name(12, data)

    qtype_val = int.from_bytes(data[pos:pos+2], 'big')
    qtype_str = RECORD_TYPES.get(qtype_val, str(qtype_val))
    qclass = int.from_bytes(data[pos+2:pos+4], 'big')

    raw_req = data[12:pos+4]
    req = DNSRequest(domain, qtype_str, qclass, raw_req)

    return pos+4, req

def extract_record(pos: int, data: bytes):
    pos, domain = parse_name(pos, data)

    rtype_val = int.from_bytes(data[pos:pos+2], 'big')
    rtype_str = RECORD_TYPES.get(rtype_val, str(rtype_val))
    rec_class = int.from_bytes(data[pos+2:pos+4], 'big')

    ttl = int.from_bytes(data[pos+4:pos+8], 'big')
    rdlen = int.from_bytes(data[pos+8:pos+10], 'big')

    if rtype_str == 'IPv4':
        rec_info = data[pos+10:pos+10+rdlen]
    else:
        _, rec_info = parse_name(pos+10, data)

    record = DNSRecord(domain, rtype_str, rec_class, ttl, rec_info)

    return pos+10+rdlen, record

def start_dns_server():
    port = 53
    ip = '127.0.0.1'
    timeout = 2
    cache_storage = DNSCacheStorage()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((ip, port))
        sock.settimeout(timeout)

        while True:
            try:
                packet, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            print("Incoming request from:", addr)
            new_pos, req = extract_request(packet)
            if req in cache_storage:
                print("Serving response from cache")
                parser = DNSParser(packet, cache_storage)
                response_packet = parser.build_response(req)
            else:
                print("Requesting answer from remote server")
                response_packet, status = fetch_remote_data(packet)
                if status:
                    DNSParser(response_packet, cache_storage)

            sock.sendto(response_packet, addr)

if __name__ == '__main__':
    try:
        start_dns_server()
    except KeyboardInterrupt:
        print("Shutting down server.")
