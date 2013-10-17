import socket
import paramiko
import traceback
import os


class SSHConnection:
	def __init__(self, hostname, username, password, port = 22):
		paramiko.util.log_to_file('paramiko_ssh.log')
		self.hostname = hostname
		self.port = port
		self.username = username
		self.password = password
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #IPv4
		except Exception as e:
			print('*** Socket creation failed: ' + str(e))
			traceback.print_exc()
			return
	
	def connect(self):
		try:
			self.sock.connect((self.hostname, self.port))
		except Exception as e:
			print('*** Connection failed: ' + str(e))
			traceback.print_exc()
			return
		try:
			self.t = paramiko.Transport(self.sock)
			try:
				self.t.start_client()
			except paramiko.SSHException:
				print('*** SSH negotiation failed.')
				return
			
			try:
				self.keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
			except IOError:
				print('*** Unable to open host keys file')
				self.keys = {}
			
			key = self.t.get_remote_server_key()
			if not self.hostname in self.keys:
				print('*** WARNING: Unknown host key!')
			elif not self.keys[hostname].has_key(key.get_name()):
				print('*** WARNING: Unknown host key!')
			elif self.keys[hostname][key.get_name()] != key:
				print('*** WARNING: Host key has changed!!!')
			else:
				print('*** Host key OK.')
			
			self.t.auth_password(self.username, self.password)
			if not self.t.is_authenticated():
				print('*** Authentication failed')
				self.t.close()
				return
			self.chan = self.t.open_session()
			self.chan.get_pty()
			self.chan.invoke_shell()
		except Exception as e:
			print('*** Caught exception: ' + str(e.__class__) + ':' + str(e))
			traceback.print_exc()

	def send_and_receive(self, command):
		if type(command) != type(bytes())
			try:
				command = command.encode()
			except AttributeError:
				print('*** Expected a string or bytestring as input')
				traceback.print_exc()
				return

		command = command.strip() + b'\n'
		self.t.chan.send(command)
		return self.t.chan.recv(4096)
	
	def close(self):
		self.t.chan.close()
		self.t.close()