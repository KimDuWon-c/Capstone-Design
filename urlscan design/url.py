import requests

import time
import codecs
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"
  }
f=codecs.open("VT_Detect.txt","r","utf-8")
reassemble = f.read().splitlines()
reassemble_2 = [i.split('/')[2] for i in reassemble]
apikey= "2b216836dde92f155d128f683ef784836f56a9bcb442b749959a5b3ec9e83da1"

for line_num, line in enumerate(reassemble_2):
    print('%d) %s'%(line_num+1,line) + ' ==>',end='')
    print("line is here : "+line)    
    try:
        params = {'apikey': apikey, 'resource':line}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        json_response = response.json()
        positives_Json = json_response.get("positives")
        response_Json = json_response.get("response_code")
        print(json_response)
        print (positives_Json)
        time.sleep(14.5)
        if response_Json == 0:
          continue
    
        elif positives_Json > 0:
          f=open('VT_Positves.txt','a')
          print("Write Detected : "+ positives_Json)
          f.writelines("Detected : " + positives_Json + line)
        elif positives_Json == 0:
          print ("Non Detect")
        
        else:
          print ("Error")
   
    finally:
      print ('Non Error')
