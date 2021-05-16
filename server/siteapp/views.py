from django.shortcuts import render
from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseNotFound
import subprocess
import json
import requests
import os
from django.core.files.storage import FileSystemStorage
from django.urls import reverse
import time

# Create your views here.

API_KEY = "45e688ec223ad38565518fd51c7455a1a9f219638959a7053b53eb8fbb7e623a"
BASE_DIR = os.getcwd()


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
        while status != 'completed' and cnt != 5:
            file_json = file_report(file_id)
            status = file_json['data']['attributes']['status']
            cnt += 1
            print(status, cnt)
            time.sleep(5)

        file_sha = file_json['meta']['file_info']['sha256']
        # excute_dangerzone(BASE_DIR+'/'+media_dir+'/'+file_name, file_sha)
        excute_dangerzone(file_name, file_sha)
        return vtchart(request, file_json['data']['attributes'], file_json['meta']['file_info']['sha256'])


def excute_dangerzone(name, hash):
    # 경로 표시
    # window: \\ , linux: /
    print('-'*10 + 'Excute Dangerzone' + '-' * 10)
    file_rm = BASE_DIR+'\\media\\suspicious_files\\' + hash + '\\safe-output.pdf'
    if os.path.isfile(file_rm):
        os.remove(file_rm)
    
    uploadpath = BASE_DIR + '\\media\\' + hash
    path = BASE_DIR+'\\media\\suspicious_files\\'+name
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

def file_download(request):

    fs = FileSystemStorage()
    filename = os.getcwd()+'/media/siteapp/files/example.pdf'
    print(os.getcwd())
    if fs.exists(filename):
        with fs.open(filename) as pdf:
            response = HttpResponse(pdf, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="example.pdf"'
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


def vtchart(request, file_data, file_sha):
    if file_data == '':
        HttpResponseNotFound('NOT FOUND')
    if file_data['stats']['malicious'] > 0 or file_data['stats']['suspicious'] > 0:
        flag = True
    else:
        flag = False

    # 0: malicious, 1: undetected, 2: type-unsupported, 3: etc
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

    return render(request, 'report.html', context={'data': re_data, 'flag': flag, 'hash': file_sha})