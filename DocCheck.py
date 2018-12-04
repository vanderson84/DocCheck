import requests, sys,json,hashlib

BUF_SIZE = 65536  
# Here you have to use your VIrusTotal API
user_api_key = 'Put your Virustotal API here'
md5 = hashlib.md5()

with open(sys.argv[1], 'rb') as f:
    while True:
        data = f.read(BUF_SIZE)
        if not data:
            break
        md5.update(data)

params = {
    'apikey': user_api_key,
    'resource': md5.hexdigest()
    }

# making json better
def pp_json(json_thing, sort=True, indents=4):
    if type(json_thing) is str:
        print(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
    else:
        print(json.dumps(json_thing, sort_keys=sort, indent=indents))
        return None

response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)

json_response = response.json()

pretty_json = pp_json(json_response)

print("MD5: {0}".format(md5.hexdigest()))
print(pretty_json)
