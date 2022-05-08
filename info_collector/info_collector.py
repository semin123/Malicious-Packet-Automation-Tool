import json

class Info_collector():
    # report_info : yara 매칭 스트림 큐 summary_info: summary에 들어갈 정보 받아오는 리스트 yara_match: yara 매칭 이름 가져오기
    def __init__(self,report_info,summary_info,yara_match):
        self.report_info = report_info
        self.summary_info = summary_info
        self.yara_match = yara_match
        self.extract_http_data()


    def extract_http_data(self):
        print('Info collector(process) initiated.\t')
        total_json = {}
        summary = {}
        total_json['Summary'] = {}
        matched_summary = {}
        matched_summary['Matched_summary'] = []
        matched_stream_session = {}
        matched_stream_session['Matched stream session'] = []
        matched_http_request = {}
        matched_http_request['HTTP request'] = []
        info = []
        rule_name = []

        while True:
            yara_packet = self.report_info.get()
            # 큐에서 값 빼서 모두 리스트에 저장
            info.append(yara_packet)
            #전 모듈 큐에서 데이터 다 받으면 종료
            if yara_packet == -1:
                break

        # summary 정보 추출
        summary['PCAP name'] = self.summary_info[0]
        summary['Analysis Time'] = self.summary_info[1]
        summary['Capture Time'] = self.summary_info[2]
        summary['Total Packets'] = self.summary_info[3]

        total_json['Summary'] = summary

        # 매칭된 스트림 정보 추출
        for i in range(len(info)):
            # -1이 나오면 종료
            if info[i] == -1:
                break
            else:
                # 매칭된 스트림과 룰정보
                matching_info = {}
                matching_info['matching stream'] = info[i][0].tcp.stream
                # matching_info['matching Rule'] = self.yara_match[i]

                matched_summary['Matched_summary'].append(matching_info)

                # 매칭된 스트림 통신 정보(한 json파일에 쭉 연결됨)
                for j in range(len(info[i])):
                    session_data = {}
                    session_data['stream num'] = info[i][j].tcp.stream
                    session_data['time'] = str(info[i][j].sniff_time.replace(microsecond=0))
                    session_data['src_ip'] = info[i][j].ip.src
                    session_data['src_port'] = info[i][j].tcp.srcport
                    session_data['dst_ip'] = info[i][j].ip.dst
                    session_data['dst_port'] = info[i][j].tcp.dstport
                    session_data['protocol'] = info[i][j].highest_layer

                    matched_stream_session['Matched stream session'].append(session_data)

                    #매칭된 스트림에 존재하는 http request 정보들
                    if info[i][j].highest_layer == 'HTTP':
                        http_request_data = {}
                        http_request_data['stream num'] = info[i][j].tcp.stream
                        http_request_data['src ip'] = info[i][j].ip.src
                        http_request_data['src port'] = info[i][j].tcp.srcport
                        http_request_data['dst ip'] = info[i][j].ip.dst
                        http_request_data['dst port'] = info[i][j].tcp.dstport
                        http_request_data['Host name'] = info[i][j].http.host
                        http_request_data['Method'] = info[i][j].http.Request_method
                        http_request_data['Uri'] = info[i][j].http.Request_uri

                        matched_http_request['HTTP request'].append(http_request_data)

                    else:
                        continue

                total_json['Matched stream session'] = matched_stream_session
                total_json['HTTP request'] = matched_http_request
        total_json['Matched summary'] = matched_summary

        #json으로 뽑기
        with open('packet_report' + '.json', 'w', encoding="utf-8") as make_file:
            json.dump(total_json, make_file, ensure_ascii=False, indent="\t")

            # 매칭된 스트림 별로 json 뽑는 방식으로 할 때 필요
            # total_json['Matched_summary'].clear()
            # total_json['Matched stream session'].clear()
            # total_json['HTTP request'].clear()
        print('Info collector(process) done.\t')
