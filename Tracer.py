import argparse
import re
import subprocess
from ipwhois import IPWhois, IPDefinedError

class Tracer:
    def __init__(self, target):
        self.regex = r'(?:\d{1,3}\.){3}\d{1,3}'
        self.target = target
        self.hops = []

    def traceroute(self):
        try:
            result = subprocess.run(
                ['traceroute', '-n', self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            output = result.stdout
        except Exception as e:
            print("Error in traceroute: {}".format(e))
            return []

        ip_list = []

        for line in output.splitlines()[1:]:
            parts = line.split()

            if not parts:
                continue

            if "*" in parts:
                ip_list.append(None)
            else:
                ip_candidate = parts[1]

                if re.match(self.regex, ip_candidate):
                    ip_list.append(ip_candidate)
                else:
                    ip_list.append(None)
        self.hops = ip_list
        return ip_list

    def get_as_info(self, ip):
        try:
            whois = IPWhois(ip)
            result = whois.lookup_whois()
            asn = result.get('asn')

            return asn
        except IPDefinedError as e:
            return None
        except Exception as e:
            return None

    def run(self):
        route = self.traceroute()
        result = []

        for idx, ip in enumerate(route, start=1):
            if ip is None:
                result.append((idx, None, "No response"))
            else:
                asn = self.get_as_info(ip)
                result.append((idx, ip, asn))
        return result

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Tracer for IP adresses."
    )
    parser.add_argument('target', help="IP adress or domain")

    args = parser.parse_args()

    tracer = Tracer(args.target)

    route = tracer.run()

    print("Хоп\tIP-адрес\t\tAS")
    for hop in route:
        hop_no, ip, asn = hop
        print(f"{hop_no}\t{ip or '-'}\t\t{asn or '-'}")