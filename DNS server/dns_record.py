from constants import domain_to_bytes, RECORD_CODES


class DNSRecord:
    def __init__(self, domain: str, rec_type: str, rec_class: int, ttl: int, rec_info):
        self.domain = domain
        self.rec_type = rec_type
        self.rec_class = rec_class
        self.ttl = ttl
        self.rec_info = rec_info
        self.record_bytes = self.build_record()

    def build_record(self) -> bytes:
        packet, _ = domain_to_bytes(self.domain)

        if self.rec_type in RECORD_CODES:
            record_code = RECORD_CODES[self.rec_type]
        elif self.rec_type.isdigit():
            record_code = int(self.rec_type)
        else:
            raise KeyError(self.rec_type)

        packet += int.to_bytes(record_code, 2, 'big')
        packet += int.to_bytes(self.rec_class, 2, 'big')
        packet += int.to_bytes(self.ttl, 4, 'big')

        if self.rec_type == 'NameServer':
            ns_domain = self.rec_info.rstrip('.')
            ns_bytes, ns_len = domain_to_bytes(ns_domain)
            packet += int.to_bytes(ns_len + 1, 2, 'big') + ns_bytes + b'\x00'
        else:
            if isinstance(self.rec_info, str):
                rec_data = self.rec_info.encode('utf-8')
            else:
                rec_data = self.rec_info

            packet += int.to_bytes(len(rec_data), 2, 'big') + rec_data

        return packet

    def __str__(self):
        return "domain: {0}, type: {1}, class: {2}, ttl: {3}, data: {4}".format(
            self.domain,
            self.rec_type,
            self.rec_class,
            self.ttl,
            self.rec_info
        )
