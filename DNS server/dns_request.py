class DNSRequest:
    def __init__(self, name: str, rec_type: str, rec_class: int, raw_data: bytes):
        self.name = name
        self.type = rec_type
        self.rec_class = rec_class
        self.raw_data = raw_data

    def __str__(self):
        return "name: {0}, type: {1}, class: {2}".format(self.name, self.type, self.rec_class)
