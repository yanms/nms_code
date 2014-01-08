"""
The TelnetConnection class contains generic connection routines with an Telnet implementation

Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option) 
any later version.
"""

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
		"""Opens the SSH connection
		
		Return value:
		Integer
		"""
		try:
			self.tn.open(host = self.hostname, port = self.port)
			self.tn.read_until(b'login: ')
			self.tn.write(self.password.encode() + b'\n')
			self.tn.read_lazy()			
		except:
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
		self.tn.send(command)
		time.sleep(delay)
		return self.tn.read_some()

	def receive(self):
		return self.tn.read_some()

	def send(self, text):
		return self.tn.send(text)

	def close(self):
		self.tn.close()