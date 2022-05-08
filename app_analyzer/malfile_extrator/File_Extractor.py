import os
import hashlib
import json
from threading import Thread
import re
import base64

class File_Extractor(Thread):
    def __init__(self, input_queue1, input_queue2):
        Thread.__init__(self)
        self.yara_stream_queue = input_queue1
        self.queue_hash = input_queue2
    def run(self):
        print('File extractor(thread) initiated.\t')
        try:
            os.mkdir("./extract")  # 폴더 생성
        except OSError:
            if not os.path.isdir("./extract"):  # 이미 폴더가 생성되어 있을 때 오류 방지
                raise
        output_File = []
        mal_file_hash = []
        file_count = 0  # 파일 개수를 카운트 하기 위한 변수
        while True:
            http_stream= self.yara_stream_queue.get()
            if http_stream == -1:  # endFlag 가 읽히면 더 받아올 스트림이 없는 것이므로 반복문 종료
                break
            for packet in http_stream:
                if 'HTTP' in packet:
                    try:
                        if packet.http.content_type:
                            binary = packet.http.file_data.binary_value
                    except:
                        pass
                    else:
                        output_File.append(binary)
                        matched = re.findall('(([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?)|([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)', str(binary))
                        for mat in matched :
                            for string in mat :
                                if string :
                                    decoded_str = base64.b64decode(string)
                                    if len(str(decoded_str)) > 500 :
                                        output_File.append(decoded_str)
                    
        for index in range(len(output_File)):
#            print(index, type(output_File[index]))
            op_file = open("./extract/extract{}.bin".format(index), "wb")
            op_file.write(output_File[index])
            op_file.close()
            mal_file_hash.append(hashlib.sha256(output_File[index]).hexdigest())
            file_count += 1
        for hash in mal_file_hash:
            self.queue_hash.put(hash)
        self.queue_hash.put(-1)
        print(f'File extractor(thread) done. extracted files : {file_count}\t')


