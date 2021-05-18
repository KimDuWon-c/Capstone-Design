from django.shortcuts import render
from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseNotFound
import subprocess
import json
import requests
import os
import hashlib
import base64, codecs, time
from django.core.files.storage import FileSystemStorage
from django.urls import reverse
import time
from .models import Post

# Create your views here.
BASE_DIR = os.getcwd()


def home(request):
    return render(request, "page_home.html")

def info(request):
    return render(request, "page_info.html")
# Create your views here.
def index(request):
    print("Receive File or URL")
    if request.method == 'POST' and request.FILES['file']:
        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name
        media_dir = 'media/suspicious_files'
        file_rm = BASE_DIR + '/' + media_dir + '/' + file_name
        if os.path.isfile(file_rm):
            os.remove(file_rm)
        fs = FileSystemStorage(location=media_dir)
        fs.save(file_name, uploaded_file)
        file_id = file_upload(media_dir+'/'+file_name)
        status = ''
        cnt = 0
        while status != 'completed' and cnt != 10:
            file_json = file_report(file_id)
            status = file_json['data']['attributes']['status']
            cnt += 1
            print(status, cnt)
            # time.sleep(10)

        file_sha = file_json['meta']['file_info']['sha256']
        excute_dangerzone(BASE_DIR+'/'+media_dir+'/'+file_name, file_sha)
        with open(BASE_DIR + '/media/'+file_sha+'/report.json', 'w') as f:
            json.dump(file_json, f, indent=4)
        return convey_id_hash(request, file_sha)

def url(request):
    if request.method == "POST" and request.POST['testurl']:
        url = request.POST['testurl']
        url_bytes = url.encode('ascii')
        url_base64 = base64.b64encode(url_bytes)
        url_base64_str = url_base64.decode('ascii')
        return render(request, "url.html", context={'url': url_base64_str})

def url_report(request, url):
    url_base64 = url
    url_bytes = base64.b64decode(url)
    url_real = url_bytes.decode('ascii')
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip,  My Python requests library example client or username"
        }
    q=codecs.open("VT_Detect.txt","w",encoding = "utf-8")
    q.write(url_real)
    q.close()
    f=codecs.open("VT_Detect.txt","r",encoding = "utf-8")
    reassemble = f.read().splitlines()
    print(reassemble)
    reassemble_2 = [i.split('/')[2] for i in reassemble]
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
    p=codecs.open("VT_Detect.txt", "w", encoding ="utf-8")
    p.write("")
    p.close()
    data = zip(detectTrueProg, detectTrueType) 
    if (positives_Json == 0 and unrated == 0):
        return render(request, "page1.html", context= {'url': url_real, 'detectTrueProg': detectTrueProg, 'detectTrueType' : detectTrueType, 'unrated': unrated})
    elif (positives_Json == 0 and unrated == 1):
        return render(request, "page2.html", context= {'url': url_real, 'detectTrueProg': detectTrueProg, 'detectTrueType' : detectTrueType, 'unrated': unrated})
    elif (positives_Json <=3 and malwcount <= 1 and phicount == 0):
        return render(request, "page3.html", context= {'url': url_real, 'detectTrueProg': detectTrueProg, 'detectTrueType' : detectTrueType, 'unrated': unrated})
    else:
        return render(request, "page4.html", context= {'url': url_real, 'detectTrueProg' : detectTrueProg, 'detectTrueType' : detectTrueType, 'data': data, 'unrated': unrated})

def excute_dangerzone(path, hash):
    print('-'*10 + 'Excute Dangerzone' + '-' * 10)
    file_rm = BASE_DIR+'/media/' + hash + '/safe-output.pdf'
    if os.path.isfile(file_rm):
        os.remove(file_rm)
    
    uploadpath = BASE_DIR + '/media/' + hash
    args = [
        "docker",
        "run",
        "--network",
        "none",
        "-v",
        f"{path}:/tmp/input_file",
        "-v",
        f"{uploadpath}:/safezone",
        "c0natus/cap:0.0",
        "document-to-pdf.sh"
    ]
    try:
        p = subprocess.run(args, timeout=60)
    except subprocess.TimeoutExpired:
        print_flush("Error converting document to PDF, LibreOffice timed out after 60 seconds")
        sys.exit(1)

    if p.returncode != 0:
        print_flush(f"Conversion to PDF failed: {p.stdout}")
        sys.exit(1)

def file_download(request, hash):
    print(request)
    print(hash)
    fs = FileSystemStorage()
    filename = BASE_DIR+'/media/'+ hash + '/safe-output.pdf'
    if fs.exists(filename):
        with fs.open(filename) as pdf:
            response = HttpResponse(pdf, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="safe-output.pdf"'
            return response
    else:
        print("None")
        return HttpResponseRedirect(reverse('index'))


def file_upload(orgfile, timeout=None, proxies=None):
    if not os.path.isfile(orgfile):
        raise Exception('File not found.')
    base_url = 'https://www.virustotal.com/api/v3/files'
    file_size = os.path.getsize(orgfile)
    headers = {
        'x-apikey': API_KEY,
    }
    # 32 MB 기준
    if file_size >= 33554432:
        with open(orgfile, 'rb') as f:
            data = {'file': f.read()}
            try:
                response = requests.get(base_url + '/upload_url',
                                        headers=headers,
                                        proxies=proxies,
                                        timeout=timeout)

                if response.status_code != 200:
                    raise Exception(response)

                upload_url = response.json()['data']
                response = requests.post(upload_url,
                                         headers=headers,
                                         files=data,
                                         proxies=proxies,
                                         timeout=timeout)
                if response.status_code != 200:
                    raise Exception(response)

                return response.json()['data']['id']

            except Exception as e:
                print(e)
                exit(1)
    else:
        with open(orgfile, 'rb') as f:
            data = {'file': f.read()}
            try:
                response = requests.post(base_url,
                                         headers=headers,
                                         files=data,
                                         proxies=proxies,
                                         timeout=timeout)

                if response.status_code != 200:
                    raise Exception(response)

                return response.json()['data']['id']

            except Exception as e:
                print(e)
                exit(1)


def file_report(file_id):
    headers = {
        'x-apikey': API_KEY,
        'Accept': 'application/json',
    }
    response = requests.get(
        'https://www.virustotal.com/api/v3/analyses/{}'.format(file_id), headers=headers)
    return response.json()


def vtchart(request, hash, pk):
    print('-'*10 + 'VirusTotal Malicious Report' + '-'*10)
    print(pk)
    file_path = BASE_DIR + "/media/" + hash + "/report.json"
    with open(file_path, "r") as f:
        file_json = json.load(f)
    file_data = file_json['data']['attributes']
    status = file_json['data']['attributes']['status']
    if file_data['stats']['malicious'] > 0 or file_data['stats']['suspicious'] > 0:
        flag = True
    else:
        flag = False

    # 0: malicious, 1: suspicious, 2: undetected, 3: type-unsupported, 4: etc
    re_data = [[] for _ in range(5)]
    for e in file_data['results']:
        base = file_data['results'][e]
        if base['category'] == 'malicious':
            re_data[0].append((base['engine_name'], base['result']))
        elif base['category'] == 'suspicious':
            re_data[1].append((base['engine_name'], base['result']))
        elif base['category'] == 'undetected':
            re_data[2].append((base['engine_name'], 'undetected'))
        elif base['category'] == 'type-unsupported':
            re_data[3].append((base['engine_name'], 'type-unsupported'))
        else:
            re_data[4].append((base['engine_name'], base['category']))

    return render(request, 'report.html', context={'check': status, 'data': re_data, 'flag': flag, 'hash': hash})


def convey_id_hash(request, file_sha):
    file_page = Post.objects.create(
        postname=str(file_sha)
    )
    hash_name = file_page.postname
    pk = file_page.id
    return render(request, "id.html", context={'id': pk, 'hash': hash_name})
