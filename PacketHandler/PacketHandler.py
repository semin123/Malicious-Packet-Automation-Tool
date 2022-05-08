from multiprocessing import Process, Queue
from threading import Thread


class PacketHandler():
    def __init__(self, queue_packet, queue_collection) :
        print('PacketHandler(process) initiated.\t')

        self.queue_thread_TCP = Queue()

        # UDP패킷만 put할 큐 생성
        # self.queue_thread_UDP = Queue()

        # TCP 스트림별로 모아준 큐
        self.queue_stream_coll = Queue()


        self.thread_transport_pc = Thread(target=self.packet_protocal_checker_transprotlayer, name='t_checker', args=(queue_packet,),)
        self.thread_tcp_stream = Thread(target=self.defragmenting, name='stream_collector', args=(),)
        self.thread_http_collector = Thread(target=self.collect, name='a_checker', args=(queue_collection,),)

        self.thread_transport_pc.start()
        self.thread_tcp_stream.start()
        self.thread_http_collector.start()


        self.thread_transport_pc.join()
        self.thread_tcp_stream.join()
        self.thread_http_collector.join()
        

        self.queue_thread_TCP.close()
        self.queue_stream_coll.close()

        # self.queue_thread_UDP.close()
        # self.queue_thread_UDP.join_thread()

        self.queue_thread_TCP.join_thread()        
        self.queue_stream_coll.join_thread()
        print('PacketHandler(process) done.\t')



    def packet_protocal_checker_transprotlayer(self, queue_packet):
        print('TCP layer checker(thread) initiated.')
        # 테스트를 위해 패킷 갯수를 세어 줌. 추후에 다른 프로세스에서 읽었을 때, 같은 값이 나오는지 확인용
        count_packet_TCP = 0
        # count_packet_UDP = 0
        # endFlag가 올때까지 무한 반복. endFlag는 -1 값으로 지정함
        while True:
            # queue_packet 이라는 큐에서 데이터를 한개씩 빼내어서 읽음.
            # queue_packet은 pacp_rp 모듈에서 하나씩 패킷을 읽어서 즉시 넣어주는 큐
            processingPacket = queue_packet.get()

            # endFlag가 등장하면 반복문 탈출
            # (따라서 각 모듈을 개발하는 사람들은 반드시 큐의 마지막에 endFlag를 삽입해주어야 함)
            if processingPacket == -1:
                break

            # 읽어들인 패킷의 레이어 층에 TCP가 존재하면 queue_thread_TCP에 put함
            # 추가적으로 TCP패킷 수를 1증가시켜서 테스트를 위해 카운팅함
            elif "IP" in str(processingPacket.layers):
                if "TCP" in str(processingPacket.layers):
                    self.queue_thread_TCP.put(processingPacket)
                    count_packet_TCP += 1
                # elif "UDP" in str(processingPacket.layers):
                #     self.queue_thread_UDP.put(processingPacket)
                #     self.count_packet_UDP += 1

            # print("\r\t\t\t\t\t transport_pc process : %d packet" % count_packet_TCP, end="")

        # 프로세스 종료 알림
        # print("\ntransport_pc end")
        # print("input Queue_thread_TCP count number : ", count_packet_TCP)
        # print("\n\n")

        # endFlag 삽입
        self.queue_thread_TCP.put(-1)
        # self.queue_thread_UDP.put(-1)
        print('Transport layer checker(thread) done.')



    def defragmenting(self):
        print('Stream collector(thread) initiated.')
        count_coll = 0
        result = {}
        result_check = []
        while True:
            TCP_Packet = self.queue_thread_TCP.get()  # 큐로 들어오는 값을 바로바로 넣어줌
            if TCP_Packet == -1:  # endflag면 종료
                for index, value in enumerate(result_check) :
                    if value == 0:
                        self.queue_stream_coll.put(result[index])
                        count_coll += 1

                break

            stream_index = int(TCP_Packet.tcp.stream)
            if stream_index in result:  # result 딕셔너리에 stream_index 값이 존재 하면 result에 저장

                if result_check[stream_index] > 500:
                    continue

                result[stream_index].append(TCP_Packet)

                if "RST" in str(TCP_Packet.tcp.flags.showname_value):
                    result_check[stream_index] -= 100
                elif "FIN" in str(TCP_Packet.tcp.flags.showname_value):
                    result_check[stream_index] -= 100

                if result_check[stream_index] <= -100:
                    self.queue_stream_coll.put(result[stream_index])
                    result[stream_index] = 0
                    result_check[stream_index] += 1000
                    count_coll += 1


            else:  # 처음은 result의 값이 없으므로 else부터 시작
                result[stream_index] = [TCP_Packet]
                result_check.append(0)

            # print("\r\t\t\t\t\t\t\t\t\t\t\t stream_collector process : %d stream" % count_coll, end="")

        # 프로세스 종료 알림
        # print("\nstream_coll end")
        # print("input Queue_Stream_coll count number : ", count_coll)
        # print("\n\n")

        # endFlag 삽입
        self.queue_stream_coll.put(-1)
        print('Stream collector(thread) done.')




    def collect(self,http_stream_coll):
        print('Application layer checker(thread) initiated.')

        http_cnt =0
        while True:

            TCP_stream = self.queue_stream_coll.get() #tcp_stream이 리스트로 넘어옴 ex) 147번tcp_stream=[http,tcp...]

            if TCP_stream == -1:  # endflag면 종료
                break

            for pkt in TCP_stream:  # TCP_STREAM =[TCP,HTTP ....] 들어오는 패킷을 1개씩 매칭 TCP_STREAM[i] 와 같음
                if 'HTTP' in str(pkt.layers) :  # stream_index에 http가 1개이상 있을 때 1번만 push하게 제어하기 위함
                    http_cnt +=1   # http 개수 확인
                    http_stream_coll.put(TCP_stream) #http가 있는 tcp_stream의 리스트 값을 put
                    break
            # print("\r\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t http_collector process : %d stream" % http_cnt, end="")

        # 프로세스 종료 알림
        # print("\napplication_pc end")
        # print(f"http in stream_index_count: {http_cnt}")
        # print("\n\n")

        # endFlag 삽입
        http_stream_coll.put(-1)
        print('Application layer checker(thread) done.')