import requests, json, os, time

BASE = 'http://127.0.0.1:5000'
# Add a fake blocked IP
bf = './application_data/blocked.json'
try:
    os.makedirs('./application_data', exist_ok=True)
except:
    pass
entries = []
if os.path.exists(bf):
    try:
        entries = json.load(open(bf,'r',encoding='utf-8'))
    except:
        entries = []
entries.append({'ip':'203.0.113.5','timestamp':time.strftime('%Y-%m-%d %H:%M:%S'),'action':'test','blocked':True})
with open(bf,'w',encoding='utf-8') as f:
    json.dump(entries, f, indent=2)

# call unblock endpoint
res = requests.post(BASE + '/unblock', json={'ip':'203.0.113.5'})
print('unblock status', res.status_code, res.text)
print('file now:', open(bf,'r',encoding='utf-8').read())
