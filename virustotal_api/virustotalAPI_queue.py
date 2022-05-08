import requests, time, os, json, re
class Virus_total:
    def __init__(self, file_hash):
        print('Virus total api initiated.\t')
        # 파일 추출 후 받아온 해시값 저장

        self.mal_hash = []
        while True:
            self.test = file_hash.get()
            if self.test == -1:
                break
            self.mal_hash.append(self.test)
        # 바이러스토탈 API Key
        self.my_apikey = "83503200992b6d1d46cecd5fdc70403f05a3f0a11d68c5edade33e4d90c1a35e"
        n = 0
        # 파일이 여러개일 때를 대비해 추출 파일 디렉토리에서 파일 리스트 확인
        self.file_list = os.listdir('extract')
        # json 파일이 여러개일 때 넘버링을 위해 변수 추가
        # 만약 파일 개수가 2개 이상일 때부터 2회 이상 넘버링 및 파일 스캔 할 수 있도록 조건 사용
        try:
            if len(self.file_list) > 1:
                while True:  # Main 에 삽입될 때 사용되는 queue 대응을 하기 위해 while 문으로 수정
                    file = self.file_list[n] # 맨 위 코드에서 읽어온 경로 내 파일 명을 하나씩 추가하여 해당 파일을 검사
                    self.vir_scan(file, n)
                    n += 1
                    print(n, "번째 파일 검색 완료")
                    time.sleep(10) # API 특성상 1분에 4개 파일 검색이 한계이므로 고의적으로 시간 텀을 두어 검색
                    if len(self.file_list) < n:
                        break
                # for 문으로 구현한건 롤백 대비를 위해 주석처리 후 보존
                # for file in self.file_list:
                #    self.vir_scan(file, n)
                #    n += 1
                #    print(n, "번째 파일 검색 완료")
                #  time.sleep(10)
            else:
                file = self.file_list[0]
                self.vir_scan(file, n)
#                print("파일 검색 완료")
        except:  # 2개 이상의 파일 검색 시, 더 이상 검색할게 없을 때 발생하는 오류 방지
            pass
#            print("[Virus Total] 에 검색할 파일이 없으므로 종료합니다")

    def vir_scan(self, file, numbering):
        try:
            # 추출된 파일들은 난잡하게 나오지 않도록 extract 폴더에 저장 예정
            file = 'extract/' + file
            # 파일 사이즈 확인. 단위는 Byte
            f_size = os.path.getsize(file)
            # 분석 시작 시간 확인
            # +) JSON 파일 확인 시 분석시간이 두 개임을 확인할 수 있는데 선행으로 작성된 시간은 바이러스 토탈에서 UTC를 기준으로 작성함
            # +) 우리 프로그램은 PC 시간을 기준으로 분석 시간을 포함하기 위해 별도로 시스템의 시간을 읽어서 추가함
            kr_time = time.localtime()
            Report_time = "%04d/%02d/%02d %02d:%02d:%02d" % (
                kr_time.tm_year, kr_time.tm_mon, kr_time.tm_mday,
                kr_time.tm_hour, kr_time.tm_min, kr_time.tm_sec)

            ''' 파일을 직접 스캔하지 않고 해시 값을 검색하므로 주석처리, 파일을 직접 스캔하는 경우를 대비해 남겨둠
            바이러스토탈 파일 스캔 주소
            url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
            url_scan_params = {'apikey': self.my_apikey}

            바이러스토탈 파일 스캔 시작
            response_scan = requests.post(url_scan, params=url_scan_params)
            result_scan = response_scan.json()
            scan_resource = result_scan['resource']
            '''

            # 아래 표시되는 파일 검사 안내
            # print('Virustotal FILE SCAN START : ', file, '\n')

            # 바이러스토탈 파일 스캔 결과 주소
            url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
            url_report_params = {'apikey': self.my_apikey, 'resource': self.mal_hash[numbering]}

            # 바이러스토탈 파일 스캔 결과 리포트 조회
            response_report = requests.get(url_report, params=url_report_params)

            # 점검 결과 데이터 추출
            report = response_report.json()
            if report.get('verbose_msg') == "Scan finished, information embedded":
                report_scan_sha256 = report.get('sha256')
                report_scan_md5 = report.get('md5')
                report_scan_vendors = list(report['scans'].keys())
                report_scan_vendors_cnt = len(report_scan_vendors)
                # 따로 구한 리포트 시간과 파일 사이즈 추가
                report['File_Name'] = re.sub('extract/', "", file)
                report['Report_Time'] = Report_time
                report['File_Size'] = f_size

                # 파일 스캔 결과 리포트 데이터 보기
                # print('Report Time : ', Report_time)
                # print('Scan File SHA256 : ', report_scan_sha256)
                # print('Scan File MD5 : ', report_scan_md5)
                # print('Scan File Size : ', f_size, 'byte')
                # print('Scan File Vendor CNT : ', report_scan_vendors_cnt, '\n')

                # json 파일로 결과값 출력
                output_filename = 'result_report'
                with open(output_filename + str(numbering) + '.json', 'w', encoding="utf-8") as make_file:
                    json.dump(report, make_file, ensure_ascii=False, indent="\t")
            else:
                pass
           #     print("파일 검색 결과, 악성행위가 발견되지 않았습니다.")

        except:
            pass
            #print("확인되지 않은 오류발생")
        print('Virus total api initiated.\t')
