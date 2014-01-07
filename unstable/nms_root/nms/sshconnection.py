import socket
import paramiko
import traceback
import os
import time
from django.contrib import messages

class SSHConnection:
	def __init__(self, hostname, username, password, port = 22):
		self.hostname = hostname
		self.port = port
		self.username = username
		self.password = password
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #IPv4
			self.sock.settimeout(15)
		except Exception as e:
			print('*** Socket creation failed: ' + str(e))
			traceback.print_exc()
			return
	
	def connect(self):
		try:
			self.sock.connect((self.hostname, self.port))
			self.t = paramiko.Transport(self.sock)
			self.t.start_client()
			try:
				self.keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
			except IOError:
				self.keys = {}
			
			key = self.t.get_remote_server_key()
			
			#if not self.hostname in self.keys:
			#	print('*** WARNING: Unknown host key!')
			#elif not self.keys[hostname].has_key(key.get_name()):
			#	print('*** WARNING: Unknown host key!')
			#elif self.keys[hostname][key.get_name()] != key:
			#	print('*** WARNING: Host key has changed!!!')
			#else:
			#	print('*** Host key OK.')
			self.t.auth_password(self.username, self.password)
			if not self.t.is_authenticated():
				self.t.close()
				return -1
			self.chan = self.t.open_session()
			self.chan.get_pty()
			self.chan.invoke_shell()
		except paramiko.SSHException:
			#print('*** SSHException raised')
			#traceback.print_exc()
			return -1
		except Exception as e:
			#print('*** Caught exception')
			#traceback.print_exc()
			return -1

	def send_and_receive(self, command, delay=0):
		if type(command) != type(bytes()):
			try:
				command = command.encode()
			except AttributeError:
				#print('*** Expected a string or bytestring as input')
				#traceback.print_exc()
				return

		command = command.strip() + b'\n'
		self.chan.send(command)
		time.sleep(delay)
		return self.chan.recv(4096)

	def receive(self):
		return self.chan.recv(4096)
	
	def send(self, text):
		return self.chan.send(text)
		
	def close(self):
		self.chan.close()
		self.t.close()