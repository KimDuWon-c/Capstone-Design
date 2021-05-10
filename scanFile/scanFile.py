import requests, os, json

API_KEY = "45e688ec223ad38565518fd51c7455a1a9f219638959a7053b53eb8fbb7e623a"


def file_upload(orgfile, timeout=None, proxies = None):
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
    response = requests.get('https://www.virustotal.com/api/v3/analyses/{}'.format(file_id), headers=headers)
    return response.json()


def vtchart(file_data):
    if file_data['stats']['malicious'] > 0:
        flag = True
    else:
        flag = False

    # 0: malicious, 1: undetected, 2: type-unsupported, 3: etc
    re_data = [[] for _ in range(4)]
    for e in file_data['results']:
        base = file_data['results'][e]
        if base['category'] == 'malicious':
            re_data[0].append((base['engine_name'], base['result']))
        elif base['category'] == 'undetected':
            re_data[1].append((base['engine_name'], 'undetected'))
        elif base['category'] == 'type-unsupported':
            re_data[2].append((base['engine_name'], 'type-unsupported'))
        else:
            re_data[3].append((base['engine_name'], base['category']))

    return flag, re_data


if __name__ == '__main__':
    orgfile = 'test.hwp'
    file_id = file_upload(orgfile)
    status = ''
    while status != 'completed':
        file_json = file_report(file_id)
        status = file_json['data']['attributes']['status']
    
    is_detected, refined_data = vtchart(file_json['data']['attributes'])
