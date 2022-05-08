import json, os, re, webbrowser
from json2table import convert

class print_report():
    def __init__(self):
        this_path = os.getcwd()
        chrome_path = 'C:/Program Files/Google/Chrome/Application/chrome.exe %s'
        template = open('./report_maker/report_template.html', 'r', encoding='UTF-8')
        self.html_tmp = template.read()
        # 악성 호스트 여러개일 때 json 여러 파일 대응 확인하려고 별도 폴더에 담는다고 가정
        analy_file_list = os.listdir('./relational_analysis')
        # 폴더 파일 내 json 파일만 뽑아올 수 있도록 하기 위한 변수
        analy_file = []
        mal_file = []
        for i in range(len(analy_file_list)):
            analy_temp = re.findall(r'relationaljson[0-9]', analy_file_list[i])
            if analy_temp:
                temp = analy_temp.pop(0)
                analy_file.append(temp)
            else:
                continue
        mal_file_list = os.listdir('./')
        for i in range(len(mal_file_list)):
            mal_temp = re.findall(r'result_report[0-9]', mal_file_list[i])
            if mal_temp:
                temp = mal_temp.pop(0)
                mal_file.append(temp)
            else:
                continue
        path = "./relational_analysis/"  # 악성 호스트 json 파일 경로
        output = open('./report_maker/EMP report.html', 'w')
        analy_file_num = len(analy_file)
        mal_file_num = len(mal_file)
        # 전체 패킷은 언제나 1회만 불러오므로 따로 함수로 작성
        self.html_tmp = self.full_packet_report(self.html_tmp)
        # 연관분석용 여러개일 때 html 태그를 자동 추가하기 위한 변수
        # 태그 추가하는 함수의 결과값을 담음
        creat_tag_rel = self.creat_tag_rel(analy_file_num)
        creat_vt_tab = self.creat_vt_tab(mal_file_num)
        creat_tag_vt = self.creat_tag_vt(mal_file_num)

        # 각 json 개수에 맞춰서 반복
        for cnt in range(mal_file_num):
            try:
                self.html_tmp = self.virustotal_report(cnt, self.html_tmp, creat_tag_vt, creat_vt_tab)
            except:
                continue
        for cnt in range(analy_file_num):
            try:
                self.html_tmp = self.repetition_report(cnt, self.html_tmp, path, creat_tag_rel)
            except:
                continue
        output.write(self.html_tmp)
        template.close()
        webbrowser.get(chrome_path).open(this_path + '/report_maker/EMP report.html')
        print("end")

    def full_packet_report(self, html_tmp):
        full_file = open('./packet_report.json', 'r')  # 전체 패킷 json 로드
        full_packet = json.load(full_file)
        stream_session = full_packet['Matched stream session']
        http_request = full_packet['HTTP request']
        build_direction = "LEFT_TO_RIGHT"
        table_attributes = {"style": "width:100%"}
        packet_list = convert(stream_session, build_direction=build_direction, table_attributes=table_attributes)
        http_list = convert(http_request, build_direction=build_direction, table_attributes=table_attributes)
        html_tmp = html_tmp.replace("{pcap_name}", full_packet['Summary']['PCAP name'])
        html_tmp = html_tmp.replace("{analysis_time}", full_packet['Summary']['Analysis Time'])
        html_tmp = html_tmp.replace("{capture_time}", full_packet['Summary']['Capture Time'])
        html_tmp = html_tmp.replace("{total_packets}", full_packet['Summary']['Total Packets'])
        # html_tmp = html_tmp.replace("{matched_packets}", full_packet['Summary']['Matched Packets'])
        html_tmp = html_tmp.replace("{packet_list}", packet_list)
        html_tmp = html_tmp.replace("{http_list}", http_list)

        # summary 부분에 일부 패킷만 보여주기 위해 별도 처리
        packet_list_part = list(full_packet['Matched stream session']['Matched stream session'][0:9])
        packet_list_part = {"summary" : packet_list_part }
        summary = convert(packet_list_part, build_direction=build_direction, table_attributes=table_attributes)
        html_tmp = html_tmp.replace("{sum_packet_list}", summary)

        full_file.close()
        return html_tmp

    def virustotal_report(self, cnt, html_tmp, creat_tag_vt, creat_vt_tab):
        try:
            vt_file = open('./result_report{}.json'.format(cnt), 'r')  # 바이러스 토탈 결과
            vtdic = json.load(vt_file)
            # 바토 그래프
            match_prob = round(vtdic['positives'] / vtdic['total'] * 100)
            unmatch_prob = 100 - match_prob

            vt_result = vtdic['scans']

            build_direction = "LEFT_TO_RIGHT"
            table_attributes = {"style": "width:100%"}
            vt_list = convert(vt_result, build_direction=build_direction, table_attributes=table_attributes)

            html_tmp = html_tmp.replace("{vt_tab}", creat_vt_tab)
            # 태그 or 수정할 값
            html_tmp = html_tmp.replace("{creat_vt}", creat_tag_vt)
            # vt_list 부분이 작성할 값
            html_tmp = html_tmp.replace("{creat_vt" + str(cnt) + "}", vt_list)

            html_tmp = html_tmp.replace("{vt_list"+str(cnt)+"}", vt_list)
            html_tmp = html_tmp.replace("{vt_scan_id"+str(cnt)+"}", vtdic['scan_id'])
            html_tmp = html_tmp.replace("{vt_sha1_"+str(cnt)+"}", vtdic['sha1'])
            html_tmp = html_tmp.replace("{vt_sha256_"+str(cnt)+"}", vtdic['sha256'])
            html_tmp = html_tmp.replace("{vt_md5_"+str(cnt)+"}", vtdic['md5'])
            html_tmp = html_tmp.replace("{vt_resource"+str(cnt)+"}", vtdic['resource'])
            html_tmp = html_tmp.replace(
                "{vt_rsp_code"+str(cnt)+"}", str(vtdic['response_code']))
            html_tmp = html_tmp.replace("{vt_scan_time"+str(cnt)+"}", vtdic['scan_date'])
            html_tmp = html_tmp.replace("{vt_report_time"+str(cnt)+"}", vtdic['Report_Time'])
            html_tmp = html_tmp.replace("{vt_permalink"+str(cnt)+"}", vtdic['permalink'])
            html_tmp = html_tmp.replace("{vt_verbose_msg"+str(cnt)+"}", vtdic['verbose_msg'])
            html_tmp = html_tmp.replace("{vt_total"+str(cnt)+"}", str(vtdic['total']))
            html_tmp = html_tmp.replace("{vt_positives"+str(cnt)+"}", str(vtdic['positives']))
            html_tmp = html_tmp.replace("{vt_filename"+str(cnt)+"}", vtdic['File_Name'])
            html_tmp = html_tmp.replace("{vt_filesize"+str(cnt)+"}", str(vtdic['File_Size']))

            # virus total 탭 - pie graph
            html_tmp = html_tmp.replace("{matched_prob"+str(cnt)+"}", str(match_prob))
            html_tmp = html_tmp.replace("{unmatched_prob"+str(cnt)+"}", str(unmatch_prob))


            vt_file.close()
        except:
            pass
        return html_tmp
        
    def repetition_report(self, cnt, html_tmp, path, creat_tag_rel):
        try:
            relation_file = open(path+'relationaljson{}.json'.format(cnt), 'r')  # 연관분석용 악성 호스트 분류
            relationdic = json.load(relation_file)
            build_direction = "LEFT_TO_RIGHT"
            table_attributes = {"style": "width:100%"}
            relation_list = convert(relationdic, build_direction=build_direction, table_attributes=table_attributes)
            # html tag 생성 테스트
            html_tmp = html_tmp.replace("{rel_report}", creat_tag_rel)
            html_tmp = html_tmp.replace("{rel_report" + str(cnt) + "}", relation_list)
            relation_file.close()
        except:
            pass
        return html_tmp

    # 태그 자동 추가를 위한 함수
    def creat_tag_rel(self, cnt):
        creat_tag_f = '{rel_report'
        creat_tag_b = '}'
        temp = ''
        if cnt > 0:
            for i in range(cnt):
                creat_tag = creat_tag_f + str(i) + creat_tag_b
                temp = temp + creat_tag
                creat_tag_rel_fin = temp
        elif cnt == 0:
                creat_tag_rel_fin = '{rel_report' + str(cnt) + '}'
        return creat_tag_rel_fin
    # 바이러스 토탈 수정 값들이 굉장히 많아서 태그 및 수정 값 별로 분리 및 재조합
    def creat_tag_vt(self, cnt):
        tag_f = '<div id="tab0'
        tag_m1_top = '" class="tab-content vt-active"><h1>VirusTotal Analysis result list 0'
        tag_m1 = '" class="tab-content"><h1>VirusTotal Analysis result list 0'
        tag_m2 = '</h1><div class="inner"><div class="chart-text" style="z-index:2;">{matched_prob'
        tag_m2_1 = '}%</div><canvas style="position: relative; top:0px; z-index:1;" id="matched-chart'
        tag_m2_2 = '"></canvas><script>new Chart(document.getElementById("matched-chart'
        tag_m2_3 = '"), {type: "doughnut", data: {labels: ["matched", "unmatched"],datasets: [{label: "matched",backgroundColor: ["#28859f", "#f2f2f2"],data: [{matched_prob'
        tag_m2_4 = '}, {unmatched_prob'
        tag_m2_5 = '}]}]}});</script></div><br><br><div class="area-inner"><h2>>> file information</h2><table><tr><th>Scan ID</th><td>{vt_scan_id'
        tag_m3 = '}</td></tr><tr><th>SHA1</th><td>{vt_sha1_'
        tag_m4 = '}</td></tr><tr><th>SHA256</th><td>{vt_sha256_'
        tag_m5 = '}</td></tr><tr><th>MD5</th><td>{vt_md5_'
        tag_m6 = '}</td></tr><tr><th>Resource</th><td>{vt_resource'
        tag_m7 = '}</td></tr><tr><th>Response Code</th><td>{vt_rsp_code'
        tag_m8 = '}</td></tr><tr><th>Scan Time</th><td>{vt_scan_time'
        tag_m9 = '}</td></tr><tr><th>Report Time</th><td>{vt_report_time'
        tag_m10 = '}</td></tr><tr><th>Perma Link</th><td>{vt_permalink'
        tag_m11 = '}</td></tr><tr><th>Verbose Massage</th><td>{vt_verbose_msg'
        tag_m12 = '}</td></tr><tr><th>Total</th><td>{vt_total'
        tag_m13 = '}</td></tr><tr><th>Positives</th><td>{vt_positives'
        tag_m14 = '}</td></tr><tr><th>File Name</th><td>{vt_filename'
        tag_m15 = '}</td></tr><tr><th>File Size</th><td>{vt_filesize'
        tag_m16 = '}</td></tr></table><h2>>> vt_list</h2><table>{creat_vt'
        tag_b = '}</table></div></div>'
        temp = ''
        if cnt > 0:
            for i in range(cnt):
                if i == 0:
                    tag = tag_f + str(i) + tag_m1_top + str(i+1) + tag_m2 + str(i) + tag_m2_1 + str(i) + tag_m2_2 + str(i) + tag_m2_3 + str(i) + tag_m2_4 + str(i) + tag_m2_5 + str(i) + tag_m3 + str(i) + tag_m4 + str(i) + tag_m5 + str(i) + tag_m6 + str(i) + tag_m7 + str(i) + tag_m8 + str(i) + tag_m9 + str(i) + tag_m10 + str(i) + tag_m11 + str(i) + tag_m12 + str(i) + tag_m13 + str(i) + tag_m14 + str(i) + tag_m15 + str(i) + tag_m16 + str(i) + tag_b
                else:
                    tag = tag_f+str(i)+tag_m1+str(i+1)+tag_m2+str(i)+tag_m2_1+str(i)+tag_m2_2+str(i)+tag_m2_3+str(i)+tag_m2_4+str(i)+tag_m2_5+str(i)+tag_m3+str(i)+tag_m4+str(i)+tag_m5+str(i)+tag_m6+str(i)+tag_m7+str(i)+tag_m8+str(i)+tag_m9+str(i)+tag_m10+str(i)+tag_m11+str(i)+tag_m12+str(i)+tag_m13+str(i)+tag_m14+str(i)+tag_m15+str(i)+tag_m16+str(i)+tag_b
                temp = temp + tag
                tag_vt_fin = temp
        elif cnt == 0:
                tag_vt_fin = tag_f+str(cnt)+tag_m1+str(cnt+1)+tag_m2+str(cnt)+tag_m2_1+str(cnt)+tag_m2_2+str(cnt)+tag_m2_3+str(cnt)+tag_m2_4+str(cnt)+tag_m2_5+str(cnt)+tag_m3+str(cnt)+tag_m4+str(cnt)+tag_m5+str(cnt)+tag_m6+str(cnt)+tag_m7+str(cnt)+tag_m8+str(cnt)+tag_m9+str(cnt)+tag_m10+str(cnt)+tag_m11+str(cnt)+tag_m12+str(cnt)+tag_m13+str(cnt)+tag_m14+str(cnt)+tag_m15+str(cnt)+tag_m16+str(cnt)+tag_b
        return tag_vt_fin

    def creat_vt_tab(self, cnt):
        tag_f = '<div data-tab="tab0'
        tag_f_top = '<div class="vt-active" data-tab="tab0'
        tag_m = '">list 0'
        tag_b = '</div>'
        temp = ''
        if cnt > 0:
            for i in range(cnt):
                if i == 0:
                    tab = tag_f_top + str(i) + tag_m + str(i+1) + tag_b
                else:
                    tab = tag_f + str(i) + tag_m + str(i+1) + tag_b
                temp = temp + tab
                tag_vt_tab_fin = temp
        elif cnt == 0:
            tag_vt_tab_fin = tag_f_top + str(cnt) + tag_m + str(cnt+1) + tag_b
        return tag_vt_tab_fin


