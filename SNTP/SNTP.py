import socket
import struct
import time
import datetime


def frac_from_timestamp(timestamp, bits=32):
    return int((timestamp - int(timestamp)) * (2 ** bits))


class NTPConfig:
    SYSTEM_DATE = datetime.date(*time.gmtime(0)[0:3])
    NTP_DATE = datetime.date(1900, 1, 1)
    DELTA = (SYSTEM_DATE - NTP_DATE).days * 24 * 3600  # Обычно 2208988800 секунд


class NTPMessage:
    PACK_FORMAT = "!B B B b 11I"

    def __init__(self, version=3, mode=4, time_offset=0):
        self.leap = 0
        self.version = version
        self.mode = mode
        self.stratum = 1
        self.poll = 0
        self.precision = 0
        self.root_delay = 1
        self.root_dispersion = 1
        self.reference_id = 0

        current_time = time.time() + NTPConfig.DELTA + time_offset
        self.reference_timestamp = current_time
        self.originate_timestamp = current_time
        self.receive_timestamp = current_time
        self.transmit_timestamp = current_time

    def build_packet(self):
        header = (self.leap << 6) | (self.version << 3) | self.mode

        packet = struct.pack(
            self.PACK_FORMAT,
            header,
            self.stratum,
            self.poll,
            self.precision,
            self.root_delay,
            self.root_dispersion,
            self.reference_id,
            int(self.reference_timestamp),
            frac_from_timestamp(self.reference_timestamp),
            int(self.originate_timestamp),
            frac_from_timestamp(self.originate_timestamp),
            int(self.receive_timestamp),
            frac_from_timestamp(self.receive_timestamp),
            int(self.transmit_timestamp),
            frac_from_timestamp(self.transmit_timestamp)
        )
        return packet

    def parse_packet(self, data):
        try:
            unpacked = struct.unpack(self.PACK_FORMAT, data)
            self.leap = (unpacked[0] >> 6) & 0x03
            self.version = (unpacked[0] >> 3) & 0x07
            self.mode = unpacked[0] & 0x07
            self.stratum = unpacked[1]
            self.poll = unpacked[2]
            self.precision = unpacked[3]
            self.root_delay = unpacked[4]
            self.root_dispersion = unpacked[5]
            self.reference_id = unpacked[6]
            self.reference_timestamp = unpacked[7] + unpacked[8] / (2 ** 32)
            self.originate_timestamp = unpacked[9] + unpacked[10] / (2 ** 32)
            self.receive_timestamp = unpacked[11] + unpacked[12] / (2 ** 32)
            self.transmit_timestamp = unpacked[13] + unpacked[14] / (2 ** 32)
        except struct.error:
            raise ValueError("Неверный формат NTP-пакета.")


def run_ntp_server():
    config_file = "config.txt"

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            time_offset = int(f.readline().strip())
            print("Смещение времени из файла:", time_offset, "секунд")

    except Exception as e:
        print("Ошибка чтения файла", config_file, ":", e)
        print("Используем смещение = 0")
        time_offset = 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind(("localhost", 123))
    except Exception as e:
        print("Ошибка привязки к порту 123. Возможно, нужны права администратора:", e)
        return

    sock.settimeout(60)
    print("NTP-сервер запущен на порту 123. Ожидание запросов...")

    try:
        while True:
            data, addr = sock.recvfrom(1024)
            client_msg = NTPMessage()

            try:
                client_msg.parse_packet(data)
            except ValueError as err:
                print("Ошибка разбора пакета клиента:", err)
                continue

            client_transmit_time = client_msg.transmit_timestamp

            server_receive_time = time.time() + NTPConfig.DELTA + time_offset

            response = NTPMessage(version=3, mode=4, time_offset=time_offset)

            response.originate_timestamp = client_transmit_time

            response.receive_timestamp = server_receive_time

            response.reference_timestamp = server_receive_time

            server_transmit_time = time.time() + NTPConfig.DELTA + time_offset
            response.transmit_timestamp = server_transmit_time

            packet = response.build_packet()
            sock.sendto(packet, addr)
            print("Ответ отправлен клиенту", addr)
    except socket.timeout:
        print("Тайм-аут ожидания. Завершаем работу сервера.")
    except KeyboardInterrupt:
        print("Работа сервера прервана пользователем.")
    finally:
        sock.close()


if __name__ == "__main__":
    run_ntp_server()
