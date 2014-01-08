"""
The SSHConnection class contains generic connection routines with an SSH implementation

Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option) 
any later version.
"""

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
		"""Opens the SSH connection
		
		Return value:
		Integer
		"""
		try:
			self.sock.connect((self.hostname, self.port))
			self.t = paramiko.Transport(self.sock)
			self.t.start_client()
			self.t.auth_password(self.username, self.password)
			if not self.t.is_authenticated():
				self.t.close()
				return -1
			self.chan = self.t.open_session()
			self.chan.get_pty()
			self.chan.invoke_shell()
		except paramiko.SSHException:
			return -1
		except Exception as e:
			return -1

	def send_and_receive(self, command, delay=0):
		"""Sends a command, waits for the specified delay and
		receives data
		
		Keyword arguments:
		command -- The string to send over the connection
		delay   -- The amount of seconds to sleep before calling recv (default = 0)
		
		Return value:
		Bytestring
		"""
		if type(command) != type(bytes()):
			try:
				command = command.encode()
			except AttributeError:
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