from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseNotFound
import subprocess, json, requests, os
from django.core.files.storage import FileSystemStorage
from .models import Document
from .forms import DocumentForm
from django.urls import reverse

API_KEY = "45e688ec223ad38565518fd51c7455a1a9f219638959a7053b53eb8fbb7e623a"
BASE_DIR = os.getcwd()


# Create your views here.
def index(request):
    print(f"Great! You're using Python 3.6+. If you fail here, use the right version.")
    message = 'Upload as many files as you want!'
    if request.method == 'POST' and request.FILES['docfile']:
        uploaded_file = request.FILES['docfile']
        file_name = uploaded_file.name
        media_dir = 'media/siteapp/files'
        fs = FileSystemStorage(location=media_dir)
        fs.save(file_name, uploaded_file)
        file_id = file_upload(media_dir+'/'+file_name)
        status = ''
        cnt = 0
        while status != 'completed' and cnt != 10:
            cnt += 1
            print(status, cnt)
            file_json = file_report(file_id)
            status = file_json['data']['attributes']['status']
        with open('infected.json', 'r') as f:
            file_json = json.load(f)

        file_sha = file_json['meta']['file_info']['sha256']
        return vtchart(request, file_json['data']['attributes'], file_json['meta']['file_info']['sha256'])

    # Handle file upload
    # if request.method == 'POST':
    #     form = DocumentForm(request.POST, request.FILES)
    #     if form.is_valid():
    #         newdoc = Document(docfile=request.FILES['docfile'])
    #         newdoc.save()
    #
    #         # Redirect to the document list after POST
    #         return redirect('my-view')
    #     else:
    #         message = 'The form is not valid. Fix the following error:'
    # else:
    message = ''
    form = DocumentForm()  # An empty, unbound form

    # Load documents for the list page
    documents = Document.objects.all()

    # Render list page with the documents and the form
    context = {'documents': documents, 'form': form, 'message': message}
    return render(request, 'cover.html', context)


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
    response = requests.get('https://www.virustotal.com/api/v3/analyses/{}'.format(file_id), headers=headers)
    return response.json()


def vtchart(request, file_data, file_sha):
    if file_data == '':
        HttpResponseNotFound('NOT FOUND')
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

    return render(request, 'report.html', context={'data': re_data, 'flag': flag, 'hash': file_sha})
