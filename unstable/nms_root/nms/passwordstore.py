from Crypto.Cipher import AES
from Crypto import Random
import base64

lib = None

class AESCipher:
	def __init__(self, key):
		self.key = key
		self.BS = 16
		self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
		self.unpad = lambda s: s[0:-s[-1]]

	def encrypt(self, raw):
		raw = self.pad(raw)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv+cipher.encrypt(raw))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(enc[16:]))

def __initSHMLib__():
	global lib
	if lib != None:
		lib = ctypes.cdll.LoadLibrary('./nms/c/shmlib.so')
		lib.store_password.restype = None
		lib.get_password.restype = ctypes.c_char_p

def storeMasterPassword(password):
	global lib
	if lib == None:
		__initSHMLib__()

	if len(password) != 16:
		return -1
	lib.store_password(password.encode(), 16)
	return 0

def hasMasterPassword():
	global lib
	if lib == None:
		__initSHMLib__()

	if len(lib.get_password()) == 16:
		return True
	return False

def storeEnablePassword(device, password):
	global lib
	if lib == None:
		__initSHMLib__()

	salt = base64.b64encode(Random.new().read(16))[:16].decode()
	cipher = AESCipher(lib.get_password().decode() + salt)
	device.password_enable = salt + '$' + cipher.encrypt(password).decode()
	device.save()

def storeRemotePassword(device, password):
	global lib
	if lib == None:
		__initSHMLib__()

	salt = base64.b64encode(Random.new().read(16))[:16].decode()
	cipher = AESCipher(lib.get_password().decode() + salt)
	device.password_remote = salt + '$' + cipher.encrypt(password).decode()
	device.save()

def getEnablePassword(device):
	global lib
	if lib == None:
		__initSHMLib__()

	try:
		cipher = AESCipher(lib.get_password().decode() + device.password_enable[:device.password_enable.find('$')])
		return cipher.decrypt(device.password_enable[device.password_enable.find('$')+1:])
	except:
		return b''
		

def getRemotePassword(device):
	global lib
	if lib == None:
		__initSHMLib__()

	try:
		cipher = AESCipher(lib.get_password().decode() + device.password_remote[:device.password_remote.find('$')])
		return cipher.decrypt(device.password_remote[device.password_remote.find('$')+1:])
	except:
		return b''