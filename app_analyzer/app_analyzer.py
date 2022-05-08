from multiprocessing import Process, Queue
import queue
from threading import Thread, Barrier
import logging, logging.config
import json
from app_analyzer.malfile_extrator.File_Extractor import File_Extractor
from virustotal_api.virustotalAPI_queue import Virus_total
from time import sleep
import yara
import base64
import re

class malstream_identifier_tcp(Thread):                                     # 매칭 쓰레드 객체
    def __init__(self, name, input_queue1, input_queue2, report_info, yara_match, rel_anal_queue):
        Thread.__init__(self)
        self.name = 'malstream_identifier_tcp_Thread ID : ' + str(name) 
        self.http_stream_coll = input_queue1
        self.queue_file_ex = input_queue2
        self.report_info = report_info
        self.yara_match = yara_match
        self.rel_anal_Q = rel_anal_queue
        self.rules = []
        self.rule_loader()                                                  # 룰 로드 -> 현재 [0] = http_rule
        self.start_analyze=False
        self.matchcount=0
    def run(self):                                                         
        print(f'{self.name}(thread) initiated.\t')
        global matched_streams                                              # 매치된 스트림 개수 글로벌선언
        global End_Flag                                                     # 큐의 마지막을 get()하는경우 End_Flag
        global queue_barrier                                                # 글로벌 queue barrier
        self.start_analyze = False                                          # 스트림이 정상적으로 입력되었고 분석 준비가 되었다
        self.empty_status = False                                           # get()결과가 없는경우 empty_status를 True로 설정. 이 경우 0.5초간 lock을 걸고 continue를 통해 루프를 재시작
        while True:
            try:
                if End_Flag == True:
                    print(f'{self.name}(thread) done.\t')
                    queue_barrier.wait()                                    # barrier 대기. if 모든 쓰레드가 barrier에 도달하면 pass
                    break
                elif End_Flag == False:
                    self.stream_getter()                                    # 1개 스트림 getter
                if self.empty_status == True:
                    sleep(0.5)
                    self.empty_status = False
                    continue
                elif self.empty_status == False:
                    pass
                if self.start_analyze == True:                      
                    self.yara_matcher()                                     # start_analyze 가True인경우 해당 스트림에 대한 분석을 시작 
                    self.start_analyze = False
                elif self.start_analyze == False:
                    pass
            except:
                pass

    def stream_getter(self):
        global End_Flag
        try:
            self.tmp_stream=self.http_stream_coll.get(block=False)          # 논 블로킹 방식으로 큐 아이템을 get
        except queue.Empty:                                                 # 논 블로킹 큐 get 방식에서 return이 없는경우 queue.Empty exception이 발생
            self.empty_status=True                                          # empty_status를 True로 변경하고 루프 재시작 대기
        except:
            pass
        else:
            if self.tmp_stream == -1:                                       # 큐의 마지막 아이템 (-1) 인경우 End_Flag를 True로 설정
                End_Flag=True                                               
                self.empty_status=True                                      # empty_status = True로 설정하고 루프 재시작 대기( 루프 재시작시 End_flag를 탐지하고 break 대기)
            else:
                self.start_analyze=True                                     # 정상 스트림인경우 start_analyze를 True로 설정
                self.empty_status=False                                     # empty_status = False로 설정하고 다음 코드로 진행

    def rule_loader(self):
        rule=yara.compile("app_analyzer/http_rule")
        self.rules.append(rule)                                             # http rule을 로드하고 룰 리스트에 append. (http의 경우 [0] 인덱스)

    def yara_matcher(self):                                                 # 스트림 분석함수
        global matched_streams                                      
        binary = b''
        base64_bin = b''
        base64_match = []
        for tmp_packet in self.tmp_stream:
            try:
                if tmp_packet.tcp.payload.binary_value:                     # 바이너리 value가 있는경우
                    binary += tmp_packet.tcp.payload.binary_value         # 바이너리값 추가.      # 과도한 exception 발생. 수정필요 #
            except:
                pass
            try:
                if tmp_packet.http.file_data :
                    base64_bin += tmp_packet.http.file_data.binary_value
            except:
                pass

        match_result = self.rules[0].match(data=binary)                     # 룰[0] 인덱스와 바이너리값 match
        self.matchcount += 1
        base64_match = re.findall('(([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?)|([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)', str(base64_bin))

        if match_result:
            self.queue_file_ex.put(self.tmp_stream) # 매칭된 경우 스트림을 파일추출 모듈에 put
            self.report_info.put(self.tmp_stream)
            self.rel_anal_Q.put(self.tmp_stream)
            self.yara_match.append(match_result)
            matched_streams += 1                                            # 매칭된 경우 matched_streams에 +1

        else:
            for mat in base64_match :
                for base_str in mat :
                        decoded_str = base64.b64decode(base_str)
                        if len(str(decoded_str)) > 500 :
                            self.queue_file_ex.put(self.tmp_stream) # 매칭된 경우 스트림을 파일추출 모듈에 put
                            self.report_info.put(self.tmp_stream)
                            self.rel_anal_Q.put(self.tmp_stream)
                            self.yara_match.append(match_result)
                            matched_streams += 1                                            # 매칭된 경우 matched_streams에 +1
        binary = 0
        base64_bin = b''

class app_analyzer(Process):
    def __init__(self, input_queue1, report_info, yara_match,rel_anal_queue ):
        super().__init__()
        self.threadmount = 3                                                # 쓰레드 개수. 총 패킷수에 따라 동적으로 변경 # to do #
        self.threads = []
        self.queues = []
        self.file_Ex_threads = []
        self.file_Ex_queues = []
        self.http_queue = input_queue1
        self.report_info = report_info
        self.yara_match = yara_match
        self.rel_anal_q = rel_anal_queue


    def run(self):
        print('App analyzer(process) initiated.\t')
        self.queue_constructor()
        self.thread_constructor()
        self.thread_destructor()
        Virus_total(self.queue_virusto)                                     # Virust_total api -> 전체적인  코드 수정 필요
        self.queue_destructor()
        print('App analyzer(process) done.\t')

    def queue_constructor(self):                                            # 큐 생성기
        self.queue_virusto = Queue()
        self.queue_file_Ex = Queue()

    def queue_destructor(self):                                             # 큐 소멸기
        for queue in self.queues:
            queue.close()
            queue.join_thread()
        self.queue_file_Ex.close()
        self.queue_file_Ex.join_thread()
        self.queue_virusto.close()
        self.queue_virusto.join_thread()

    def thread_constructor(self):                                            # 쓰레드 생성기
        global matched_streams
        global End_Flag
        global queue_barrier
        queue_barrier = Barrier(self.threadmount+1)
        End_Flag = False
        matched_streams = 0

        for ThreadID in range(self.threadmount):
            thread_yara = malstream_identifier_tcp(ThreadID, self.http_queue, self.queue_file_Ex,self.report_info,self.yara_match, self.rel_anal_q)
            thread_yara.start()
            self.threads.append(thread_yara)
        self.thread_file_Ex = File_Extractor(self.queue_file_Ex, self.queue_virusto)
        self.thread_file_Ex.start()
        queue_barrier.wait()                                                   # thread_yara 가 모두 break wait 상태에 있을때까지 대기
        self.queue_file_Ex.put(-1)    # 파일추출 큐에 put (-1)
        self.report_info.put(-1)
        self.rel_anal_q.put(-1)

    def thread_destructor(self):                                            # 쓰레드 소멸기
        for thread in self.threads:
            thread.join()
        self.thread_file_Ex.join()
        