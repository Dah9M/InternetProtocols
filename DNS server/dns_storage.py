import time
import pickle

class DNSCacheStorage:
    def __init__(self, filename: str = 'cache_data.p'):
        self._cache = {}
        self._filename = filename
        self.load_cache()

    def save_cache(self):
        with open(self._filename, 'wb') as f:
            pickle.dump(self._cache, f)

    def load_cache(self):
        try:
            with open(self._filename, 'rb') as f:
                self._cache = pickle.load(f)
        except (EOFError, FileNotFoundError):
            self._cache = {}
        except Exception as e:
            print('Cache load error:', e)

    def store(self, domain: str, record: object, rec_type: str, flags: bytes):
        expire_time = time.time() + record.ttl
        if domain in self._cache:
            if rec_type in self._cache[domain]:
                self._cache[domain][rec_type].append((record, expire_time, flags))
            else:
                self._cache[domain][rec_type] = [(record, expire_time, flags)]
        else:
            self._cache[domain] = {rec_type: [(record, expire_time, flags)]}

    def lookup(self, domain: str, rec_type: str):
        if domain in self._cache and rec_type in self._cache[domain]:
            valid_records = []
            for rec, exp, _ in self._cache[domain][rec_type]:
                if time.time() < exp:
                    valid_records.append(rec)
            if valid_records:
                return valid_records
            else:
                del self._cache[domain][rec_type]
        return None

    def __contains__(self, request) -> bool:
        if request.name in self._cache:
            if request.type in self._cache[request.name]:
                for rec, exp, _ in self._cache[request.name][request.type]:
                    if exp < time.time():
                        self._cache[request.name].pop(request.type)
                        return False
                return True

            if 'StartOfAuthority' in self._cache[request.name]:
                for rec, exp, _ in self._cache[request.name]['StartOfAuthority']:
                    if exp < time.time():
                        self._cache[request.name].pop('StartOfAuthority')
                        return False
                    return True

        return False
