import telnetlib
import time

class TelnetConnection:
	def __init__(self, hostname, username, password, port = 23):
		self.hostname = hostname
		self.port = port
		self.username = username
		self.password = password
		self.tn = telnetlib.Telnet(timeout=15)

	def connect(self):
		try:
			self.tn.open(host = self.hostname, port = self.port)
			self.tn.read_until(b'login: ')
			self.tn.write(self.password.encode() + b'\n')
			self.tn.read_lazy()			
		except:
			return -1

	def send_and_receive(self, command, delay=0):
		if type(command) != type(bytes()):
			try:
				command = command.encode()
			except AttributeError:
				return
		command = command.strip() + b'\n'
		self.tn.send(command)
		time.sleep(delay)
		return self.tn.read_some()

	def receive(self):
		return self.tn.read_some()

	def send(self, text):
		return self.tn.send(text)

	def close(self):
		self.tn.close()