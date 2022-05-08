from multiprocessing import Process, Queue, Manager
from threading import Thread
import sys, os, re
import pyshark
from pcap_parser.pcap_parser import Pcap_parser
from PacketHandler.Relational_analyzer import Rel_analy
from PacketHandler.PacketHandler import PacketHandler
from app_analyzer.app_analyzer import app_analyzer
from pyfiglet import Figlet
from time import sleep
from info_collector.info_collector import Info_collector
import logging, json
from report_maker.report import print_report

class Interface:
    def __init__(self):
        self.figlet = Figlet()
        self.pcap_path = 'none'
        self.report_path = 'none'
        self.pcap_status = 'NO'
        self.report_status = 'NO'
        self.check_pcap = False
        self.check_report = False
        # with open('app_analyzer/log_setting.json', 'r') as logSetting:                  # log 세팅 로드
        #     config = json.load(logSetting)
        # logging.config.dictConfig(config)                   
        # self.a_log = logging.getLogger('app_analyzer_log')

    def clearConsole(self):
        command = 'clear'
        if os.name in ('nt', 'dos'):  # If Machine is running on Windows, use cls
            command = 'cls'
        os.system(command)

    def main_console(self):
            self.clearConsole()
            print('EnteredMaliciousPacketAnalyzer v1.0')
            print(self.figlet.renderText('EMP_Analyzer'))
            print('# [INFO] PCAP path :', self.pcap_path, '[ ready : ', self.pcap_status, ']')
            # print('# [INFO] Report path :', self.report_path, '[ ready : ', self.report_status, ']')

    def select_option(self):
            print('#')
            print('# 1. Change PCAP path')
     #       print('# 2. Change Report path')
            print('# 2. Start Analyze')
            print('# 3. Exit program')
            print('#')
    def check_argv(self):
        argv_OK = False
        if(len(sys.argv) > 2):
            argv_OK = False
        elif(len(sys.argv) == 2):
            self.pcap_path = sys.argv[1]
            # self.report_path = sys.argv[2]
            argv_OK = True
            self.check_pcap = True
            self.check_report = True
        elif(len(sys.argv) == 1):
            self.pcap_path = sys.argv[1]
            argv_OK = True
            self.check_pcap = True
        else:
            argv_OK = True
        if argv_OK == False:
            print('too many args..')
            exit()
        else:
            pass
    def check_pcap_path(self):
        extension_check = False
        pcap_name = re.compile('\.(pcap|pcapng)$')
        ext_tmp = pcap_name.findall(self.pcap_path) 
        extension = ''.join(ext_tmp)
        if extension == 'pcap' or extension == 'pcapng':
            extension_check = True
        elif not extension == 'pcap' or extension == 'pcapang':
            self.pcap_path = 'none'
        if extension_check == True:
            try:
                self.pcap = pyshark.FileCapture(self.pcap_path)
                self.pcap_status = 'YES'
            except:
                self.pcap_status = 'NO'
        elif extension_check == False:
            self.pcap_status = 'NO'

    # def check_report_path(self):
    #     if os.path.isdir(self.report_path) == True:
    #         self.report_status = 'YES'
    #     else:
    #         self.report_status = 'NO'

    def EMP_Analyzer_initiator(self):
        self.check_argv()
        if self.check_pcap == True:
            self.check_pcap_path()
        # if self.check_report == True:
        #     self.check_report_path()
        while True:
            self.main_console()
            self.select_option()
            sel_op = input('option : ')
            if sel_op == '1':
                self.main_console()
                self.pcap_path = input('PCAP path : ')
                self.check_pcap_path()
                if self.pcap_path == "":
                    self.pcap_path = 'none'
            # if sel_op == '2':
            #     self.main_console()
            #     self.report_path = input('Report path : ')
            #     if self.report_path == "":
            #         self.report_path = 'none'
            #     self.check_report_path()
            if sel_op == '2':
                if self.pcap_status == 'NO':
                    print('pcap is not ready yet..')
                    pass
                # elif self.report_status == 'NO':
                #     print('report is not ready yet..')
                #     pass
                if self.pcap_status == 'YES':
                    self.start_analyze()
                    break
                else:
                    sleep(3)
                    pass
            if sel_op == '3':
                print('exiting..')
                break
        pass

    def start_analyze(self):
        manager = Manager()
        summary_info = manager.list()
        yara_match = manager.list()


        queue_packet = Queue()
        http_stream_coll = Queue()
        report_info = Queue()
        filter_information_queue = Queue()


        process_pcap_rp = Pcap_parser(self.pcap_path, queue_packet,summary_info)
        #process_packet_handler = PacketHandler(queue_packet, http_stream_coll)
        process_transport_pc = Process(target=PacketHandler, args=(queue_packet, http_stream_coll))
        process_app_analyzer = app_analyzer(http_stream_coll, report_info,yara_match,filter_information_queue)
        process_info_collector = Process(target=Info_collector,args=(report_info,summary_info,yara_match))
        process_rel_analyzer = Rel_analy(self.pcap_path, filter_information_queue)

        process_pcap_rp.start()
        process_transport_pc.start()
        #process_packet_handler.start()
        process_app_analyzer.start()
        process_info_collector.start()
        process_rel_analyzer.start()

        process_pcap_rp.join()
        process_transport_pc.join()
        #process_packet_handler.join()
        process_app_analyzer.join()
        process_info_collector.join()
        process_rel_analyzer.join()

        queue_packet.close()
        http_stream_coll.close()
        report_info.close()
        filter_information_queue.close()

        queue_packet.join_thread()
        http_stream_coll.join_thread()
        report_info.join_thread()
        filter_information_queue.join_thread()

        print_report()

if __name__ == '__main__':
   # file_path = sys.argv[1]
   EMP = Interface()
   EMP.check_argv()
   EMP.EMP_Analyzer_initiator()

