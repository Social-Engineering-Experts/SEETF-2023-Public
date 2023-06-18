from flask import Flask, request, session
from z3 import *
import random
import json
import zlib
from waitress import serve
from itsdangerous import base64_decode

keys = []

app = Flask(__name__)

with open('flag.txt') as flag:
	contents = flag.read()
	福 = contents.strip()

def solve(a_value, b_value, c_value, d_value, f_value):
	# Create the variables
	a, b, c, d, e, f = Ints('a b c d e f')

	# Set the relationships between the variables
	constraints = [And(8 <= v) for v in [a, b, c, d, e, f]]
	constraints += [a == a_value] 
	constraints += [b == b_value]
	constraints += [c == c_value]
	constraints += [d == d_value]
	constraints += [f == f_value]
	constraints += [(a ** 3) * (b**2 + c**2) * (2*d + 1) == (e**3) + (f**3)]


	# Find a satisfying solution
	s = Solver()
	s.add(constraints)
	if s.check() == sat:
		m = s.model()
		return int(m[e].as_long())
	else:
		return None
	
def decrypt_cookie(signed_cookie):
	try:
		compressed = False
		if signed_cookie.startswith('.'):
			compressed = True
			signed_cookie = signed_cookie[1:]
		data = signed_cookie.split(".")[0]
		data = base64_decode(data)
		if compressed:
			data = zlib.decompress(data)
		return json.loads(data.decode())
	except Exception as e:
		raise e

def replace_secret_key():
	if 'key' in session and session['key'] not in keys:
		keys.append(session['key'])
		app.config["SECRET_KEY"] = session['key']
	if 'session' in session and 'end' not in session:
		new_session = session['session']
		session.update(decrypt_cookie(new_session))
		replace_secret_key()

def secret(key):
	random.seed(key)
	return random.randint(8, 88888)

@app.route('/福', methods=['POST'])
def fortold():
	keys.clear()
	start = request.form.get('key')
	app.config['SECRET_KEY'] = start
	replace_secret_key()

	value = [secret(key) for key in keys]
	result = solve(*value)

	if result is not None:
		return eval(chr(result))
	else:
		return 'Bad Luck.'

if __name__ == '__main__':
	serve(app, host='0.0.0.0', port=80)
