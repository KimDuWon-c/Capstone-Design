import requests

import time
import codecs
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"
  }
url = "http://yotube.com"
q=codecs.open("VT_Detect.txt","w",encoding = "utf-8")
q.write(url)
q.close()
f=codecs.open("VT_Detect.txt","r",encoding = "utf-8")
reassemble = f.read().splitlines()
print(reassemble)
reassemble_2 = [i.split('/')[2] for i in reassemble]
apikey= "2b216836dde92f155d128f683ef784836f56a9bcb442b749959a5b3ec9e83da1"
programs = []
detectTrueProg = []
detectTrueType = []
malicount = 0
phicount = 0
malwcount = 0
unrated = 0
f.close()
# detectTrueProg 는 해당 URL이 위험하다고 감지된 프로그램 List
# detectTrueType 은 해당 프로그램이 탐지한 해당 URL의 위험요소 List
# unrated 는 위험은 감지되지 않았지만 인증되지 않은 요소가 포함되어 있는 경우가
# 존재할 경우 unrated =1 , 그렇지 않은 경우 unrated = 0
for line_num, line in enumerate(reassemble_2):
    print('%d) %s'%(line_num+1,line) + ' ==>',end='') 
    try:
        params = {'apikey': apikey, 'resource':line}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        json_response = response.json()
        positives_Json = json_response.get("positives")
        response_Json = json_response.get("response_code")
        scanr = json_response.get("scans")
        print(json_response)
        for i in range(0,88):
          programs.append(list(scanr.keys())[i])
      
        for i in range(0,88):
          if(scanr.get(programs[i]).get("detected")==True):
            print(programs[i])
            detectTrueProg.append(programs[i])
            detectTrueType.append(scanr.get(programs[i]).get("result"))
            if(scanr.get(programs[i]).get("result")=='malicious site'):
              malicount = malicount + 1

            elif(scanr.get(programs[i]).get("result")=='phishing site'):
              phicount = phicount + 1

            elif(scanr.get(programs[i]).get("result")=='malware site'):
              malwcount = malwcount + 1

          elif(scanr.get(programs[i]).get("result")=='unrated site'):
             unrated = 1

        for i in detectTrueType:
          print(i)

        print(malicount)  
        time.sleep(3)
        if response_Json == 0:
          continue
    
        elif positives_Json > 0:
          print (positives_Json)
        elif positives_Json == 0:
          print ("Non Detect")
        
        else:
          print ("Error")
   
    finally:
      print ('Non Error')
      break


p=codecs.open("VT_Detect.txt","w",encoding = "utf-8")
p.write("")
p.close()

#최종적으로 positives_Json, detectTrueProg, detectTrueType, unrated를 전달해야함.
'''
    안전 : positive_Json 0개, unrated site = 0;
    주의 : positive_Json 0개, unrated site = 1;
    위험 : positive_Json 1~3개 and Type : malware 2개 미만,phishing 미포함, malicious만 포함
    매우위험 : positive_Json 4이상 or malware 3개이상 or phishing 포함
'''