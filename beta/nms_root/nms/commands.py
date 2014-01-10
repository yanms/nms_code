"""
This module contains functions for executing commands on remote devices regardless of the protocol.

Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option) 
any later version.
"""

import nms.sshconnection as sshconnection
import nms.telnetconnection as telnetconnection
import nms.xmlparser as xmlparser
import nms.passwordstore as passwordstore
from multiprocessing import Lock
from nms.models import History
from django.utils import timezone

#Process-local cache for getInterfaces
interfaces = {}
interfacesLock = Lock()

#Process-local cache for getConnection (for interactive sessions)
connections = {}
connectionsLock = Lock()

def removeInterfaces(device):
	"""Remove cached interfaces
	
	Keyword arguments:
	device -- The device for which the cache will be emptied
	
	Return value:
	None
	"""
	global interfacesLock
	global interfaces
	
	interfacesLock.acquire()
	if device in interfaces.keys():
		del interfaces[device]
	interfacesLock.release()

def getInterfaces(command, parser, device, user):
	"""Obtains a list of all interfaces available on the device
	
	Keyword arguments:
	command -- The command used to obtain the interface names from the device
	parser  -- A regex parser to create a list of interface names from the devices console output
	device  -- The device to obtain the interface names for
	user    -- The NMS user making this request
	
	Return value:
	List of strings	
	"""
	global interfacesLock
	global interfaces
	interfacesLock.acquire()
	try:
		if not device in interfaces.keys():
			if device.pref_remote_prot == 'SSH2':
				s = sshconnection.SSHConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
			elif device.pref_remote_prot == 'Telnet':
				s = telnetconnection.TelnetConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
			else:
				return -1
			if s.connect() == -1:
				return -1
			ret = b''
			for i, arg in enumerate(command):
				if type(arg) != type(bytes()):
					History.objects.create(user_performed_task = user, action_type='Manage device', dev_id = device, action = '[dev%i] %s' % (device.dev_id, arg), date_time = timezone.now())
				if i+1 == len(command):
					ret += s.send_and_receive(arg, delay=4)
				else:
					ret += s.send_and_receive(arg)
			s.close()
			interfaces[device] = parser.parse(ret)
		return interfaces[device]
	except:
		raise
	finally:
		interfacesLock.release()

def executeTask(taskpath, device, uargs, user):
	"""Executes a (number of) command(s) to a certain device and obtains parsed cli output
	
	Keyword arguments:
	taskpath -- Used to find a specific task in the task dictionary for this device
	device   -- The device to send the commands to
	uargs    -- The user-supplied arguments
	user     -- The NMS user making this request
	
	Return value:
	String	
	"""
	xmlroot = xmlparser.get_xml_struct(device.gen_dev_id.file_location_id.location)
	taskpath = taskpath.split('|')
	commands = xmlparser.getAvailableTasks(xmlroot)
	for key in taskpath:
		if not key in commands.keys():
			return ['Invalid command']
		commands = commands[key]
	uarg_names, raw_args, parser = commands
	args = []
	for raw_arg in raw_args:
		args.append(raw_arg)
	for uarg_name in uarg_names:
		if not uarg_name in uargs.keys():
			return 'User arguments not supplied'
	for i in range(len(args)):
		for uarg_key in uargs.keys():
			if type(args[i]) == type(str()):
				args[i] = args[i].replace('%arg:' + uarg_key + '%', uargs[uarg_key])

	if device.pref_remote_prot == 'SSH2':
		s = sshconnection.SSHConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
	elif device.pref_remote_prot == 'Telnet':
		s = telnetconnection.TelnetConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
	else:
		return -1
	if s.connect() == -1:
		return -1
	ret = b''
	for i, arg in enumerate(args):
		if type(arg) != type(bytes()):
			History.objects.create(user_performed_task = user, action_type='Manage device', dev_id = device, action = '[dev%i] %s' % (device.dev_id, arg), date_time = timezone.now())
		if i+1 == len(args):
			ret += s.send_and_receive(arg, delay=4)
		else:
			ret += s.send_and_receive(arg)
	s.close()
	return parser.parse(ret)

def __createSSHConnection__(device):
	"""Creates a SSH connection used in interactive sessions
	
	Keyword arguments:
	device -- The device to connect to
	
	Return value:
	nms.sshconnection.SSHConnection object	
	"""
	connection = sshconnection.SSHConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
	connection.connect()
	connection.chan.setblocking(0)
	return connection

def __createTelnetConnection__(device):
	"""Creates a Telnet connection used in interactive sessions
	
	Keyword arguments:
	device -- The device to connect to
	
	Return value:
	nms.telnetconnection.TelnetConnection object	
	"""
	connection = telnetconnection.TelnetConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
	connection.connect()
	connection.get_socket().setblocking(0)
	return connection
	
def getConnection(user, device):
	"""Returns an open connection to a device. Connections are kept open on devices per user in the connections global dict.
	
	Keyword arguments:
	user   -- The NMS user making this request
	device -- The device to connect to
	
	Return value:
	nms.sshconnection.SSHConnection object / nms.telnetconnection.TelnetConnection object
	"""
	global connectionsLock
	global connections
	connectionsLock.acquire()
	try:
		if not user in connections.keys():
			connections[user] = {}
		if not device in connections[user].keys():
			if device.pref_remote_prot == 'SSH2':
				connections[user][device] = __createSSHConnection__(device)
			elif device.pref_remote_prot == 'Telnet':
				connections[user][device] = __createTelnetConnection__(device)
		return connections[user][device]
	except:
		raise
	finally:
		connectionsLock.release()
		
def removeConnection(user, device):
	"""Removes an connection object from the global dict
	
	Keyword arguments:
	user   -- The NMS user making this request
	device -- The device for which the connection exists
	
	Return value:
	None
	"""
	global connectionsLock
	global connections

	connectionsLock.acquire()
	try:
		if not user in connections.keys():
			return
		if not device in connections[user].keys():
			return
		connection = connections[user][device]
		connection.close()
		del connections[user][device]
	except:
		raise
	finally:
		connectionsLock.release()