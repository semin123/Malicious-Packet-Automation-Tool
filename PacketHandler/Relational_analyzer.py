import json
from multiprocessing import Process
import pyshark
import os
from scapy.all import *

class Rel_analy(Process):
    def __init__(self, file_path, filter_infomation_queue) :
        super().__init__()
        self.file_path = file_path
        self.countPacket = []
        self.startTime = []
        self.endTime = []
        self.file_name = []
        self.input_queue = filter_infomation_queue
        self.attack_ipAddr = []
        self.attack_ipAddr_hex = []

    def run(self) :
        print('Relational analysis(process) initiated.')
        self.mkdir_func()
        self.get_queue_data(self.input_queue)
        self.ip_addr_replace(self.attack_ipAddr)
        self.save_pcap(self.attack_ipAddr, self.attack_ipAddr_hex)
        self.extract_json_relational(self.attack_ipAddr)
        print('Relational analysis(process) done.')

    def mkdir_func(self):
        try:
            os.mkdir("./relational_analysis")
        except OSError:
            if not os.path.isdir("./relational_analysis"):
                raise
    def get_queue_data(self, queue) :
        while True:
            item = queue.get()
            if item == -1 :
                break
            self.attack_ipAddr.append(item[0].ip.dst)
    def ip_addr_replace(self, ipAddr) :
        for ip in ipAddr:
            self.attack_ipAddr_hex.append(ip.raw_value)
    def save_pcap(self, filter_info, file_name_val) :
        Allpkt = PcapReader(self.file_path).read_all()
        outpcap = []
        countPacket = 0
        for i in range(len(file_name_val)) :
            for pkt in Allpkt:
                if pkt.haslayer('IP') :
                    if pkt.getlayer(IP).src == str(filter_info[i]) or pkt.getlayer(IP).dst == str(filter_info[i]) :
                        outpcap.append(pkt)
                        countPacket += 1
            wrpcap(f'./relational_analysis/relational_{file_name_val[i]}.pcap', outpcap)
            self.file_name.append(f'./relational_analysis/relational_{file_name_val[i]}.pcap')
            self.countPacket.append(countPacket)
            countPacket = 0
            outpcap = []
    def extract_json_relational(self, attack_ip) :
        for i in range(len(attack_ip)):
            Relpkt = pyshark.FileCapture(self.file_name[i])
            json_data={}
            json_data['attack_ip'] = attack_ip[i]
            json_data['this_ip_count_packet'] = self.countPacket[i]
            json_data['start_connect_time'] = str(Relpkt[0].sniff_time.replace(microsecond=0))
            json_data['end_connect_time'] = str(Relpkt[self.countPacket[i]-1].sniff_time.replace(microsecond=0))
            with open(f'./relational_analysis/relationaljson{i}.json', 'w', encoding="utf-8") as make_file:
                json.dump(json_data, make_file, ensure_ascii=False, indent="\t")
            Relpkt.close()
            json_data={}

