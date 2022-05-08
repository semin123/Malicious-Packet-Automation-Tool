import multiprocessing
import pyshark
from time import sleep
import datetime
class Pcap_parser(multiprocessing.Process):
    def __init__(self, pcap_path, input_queue1,summary_info):
        multiprocessing.Process.__init__(self)
        self.queue_packet = input_queue1
        self.pcap_path = pcap_path
        self.summary_info = summary_info
        sleep(3)
    def run(self):
        print('Pcap parser(process) initiated.\t')
        pkt = pyshark.FileCapture(self.pcap_path)
        self.summary_info.append(pkt.input_filename)
        self.summary_info.append(str(datetime.datetime.now().replace(microsecond=0)))
        packet_data = pkt.next()
        self.summary_info.append(str(packet_data.sniff_time.replace(microsecond=0)))
        count_packet = 0
        while True:
            try:
                self.queue_packet.put(packet_data)
                count_packet += 1
                packet_data = pkt.next()
            except StopIteration:
                break
        self.summary_info.append(str(count_packet))
        self.queue_packet.put(-1)
        pkt.close()
        print('Pcap parser(process) done.\t')


