import nms.sshconnection as sshconnection
import nms.telnetconnection as telnetconnection
import nms.xmlparser as xmlparser
import nms.passwordstore as passwordstore
from multiprocessing import Lock
from nms.models import History

interfaces = {}
interfacesLock = Lock()

connections = {}
connectionsLock = Lock()

def removeInterfaces(device):
	global interfacesLock
	global interfaces
	
	interfacesLock.acquire()
	if device in interfaces.keys():
		del interfaces[device]
	interfacesLock.release()

def getInterfaces(command, parser, device, user):
	global interfacesLock
	global interfaces
	interfacesLock.acquire()
	try:
		if not device in interfaces.keys():
			if device.pref_remote_prot == 'SSH2' or device.pref_remote_prot == 'SSH1':
				s = sshconnection.SSHConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
			elif device.pref_remote_prot == 'Telnet':
				s = telnetconnection.TelnetConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
			else:
				return -1
			if s.connect() == -1:
				return -1
			ret = b''
			for i, arg in enumerate(command):
				History(user_id = user, action = '[dev%i] %s' % (device.dev_id, arg)).save()
				if i+1 == len(command):
					ret += s.send_and_receive(arg, delay=0.5)
				else:
					ret += s.send_and_receive(arg)
			s.close()
			interfaces[device] = parser.parse(ret)
	except:
		raise
	finally:
		interfacesLock.release()
	return interfaces[device]

def executeTask(taskpath, device, uargs, user):
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

	if device.pref_remote_prot == 'SSH2' or device.pref_remote_prot == 'SSH1':
		s = sshconnection.SSHConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
	elif device.pref_remote_prot == 'Telnet':
		s = telnetconnection.TelnetConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
	else:
		return -1
	if s.connect() == -1:
		return -1
	ret = b''
	for i, arg in enumerate(args):
		History(user_id = user, action = '[dev%i] %s' % (device.dev_id, arg)).save()
		if i+1 == len(args):
			ret += s.send_and_receive(arg, delay=0.5)
		else:
			ret += s.send_and_receive(arg)
	s.close()
	return parser.parse(ret)

def __createSSHConnection__(device):
	connection = sshconnection.SSHConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
	connection.connect()
	connection.chan.setblocking(0)
	return connection

def __createTelnetConnection__(device):
	connection = telnetconnection.TelnetConnection(device.ip, device.login_name, passwordstore.getRemotePassword(device), device.port)
	connection.connect()
	connection.get_socket().setblocking(0)
	return connection
	
def getConnection(user, device):
	global connectionsLock
	global connections
	connectionsLock.acquire()
	try:
		if not user in connections.keys():
			sshconnections[user] = {}
		if not device in connections[user].keys():
			if device.pref_remote_prot == 'SSH1' or device.pref_remote_prot == 'SSH2':
				connections[user][device] = __createSSHConnection__(device)
			elif device.pref_remote_prot == 'Telnet':
				connections[user][device] = __createTelnetConnection__(device)
		return sshconnections[user][device]
	except:
		raise
	finally:
		connectionsLock.release()
		
def removeSSHConnection(user, device):
	global connectionsLock
	global connections

	connectionsLock.acquire()
	try:
		if not user in connections.keys():
			return
		if not device in connections[user].keys():
			return
		connection = sshconnections[user][device]
		connection.close()
		del connections[user][device]
	except:
		raise
	finally:
		connectionsLock.release()