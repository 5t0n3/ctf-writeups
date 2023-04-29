#                                  _                            _   
#                                (_)                          | |  
#  ___  ___  ___ _   _ _ __ ___   _ _ __ ___  _ __   ___  _ __| |_ 
# / __|/ _ \/ __| | | | '__/ _ \ | | '_ ` _ \| '_ \ / _ \| '__| __|
# \__ \  __/ (__| |_| | | |  __/ | | | | | | | |_) | (_) | |  | |_ 
# |___/\___|\___|\__,_|_|  \___| |_|_| |_| |_| .__/ \___/|_|   \__|
#                                            | |                   
#                                            |_|                  
# Totally secure Python REPL
import importlib

# Closure needed here to only let secure_import access importilb method.
def secure_import():
	_imp = importlib.__import__
	# shout out to https://stackoverflow.com/a/47854417/8638218 for enabling security
	def __secure_import(name, globals=None, locals=None, fromlist=(), level=0):
		WHITE_LIST = ['types', 'math', 'string']
		if name in WHITE_LIST:
			library = _imp(name, globals, locals, fromlist, level)
			return library
		raise ImportError(f'{name} is not a whitelisted module;  get outta here!')
	return __secure_import

# Remove all builtins, removes cheese solves like open('./flag').read()
whitelist = set(['eval', '__import__', 'print', 'input', 'exit', 'dir', 'vars', 'getattr', 'setattr', 'isinstance'])
__builtins__.__dict__['__import__'] = secure_import()

# Delete importlib to prevent importlib.import_module
del importlib

for k in __builtins__.__dict__:
	if type(__builtins__.__dict__[k]) == type(print):
		if k not in whitelist:
			__builtins__.__dict__[k] = None


print('''Welcome to Secure REPL!
Ctrl+C to exit.''')
while 1:
	try:
		user = input(">>> ")
		print(eval(user))
	except KeyboardInterrupt:
		exit(0)
	except Exception as e:
		print(e)
