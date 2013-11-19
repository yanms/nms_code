import nms.sshconnection as sshconnection
import nms.xmlparser as xmlparser
from multiprocessing import Lock

interfaces = {}
interfacesLock = Lock()

def getInterfaces(command, parser, device):
	interfacesLock.acquire()
	try:
		s = sshconnection.SSHConnection(device.ip, device.login_name, device.password_remote, device.port)
		s.connect()
		ret = ''
		for i, arg in enumerate(command):
			if i+1 == len(command):
				ret += s.send_and_receive(arg, delay=0.5)
			else:
				ret += s.send_and_receive(arg)
		s.close()
	except:
		raise
	finally:
		interfacesLock.release()
	return parser.parse(ret)

def executeTask(taskpath, device):
	xmlroot = xmlparser.get_xml_struct(device.gen_dev_id.file_location_id.location)
	taskpath = taskpath.split('#')
	commands = xmlparser.getAvailableTasks(xmlroot)
	for key in taskpath:
		if not key in commands.keys():
			return 'Invalid command'
		commands = commands[key]
	args, parser = commands

	s = sshconnection.SSHConnection(device.ip, device.login_name, device.password_remote, device.port)
	s.connect()
	ret = ''
	for i, arg in enumerate(args):
		if i+1 == len(args):
			ret += s.send_and_receive(arg, delay=0.5)
		else:
			ret += s.send_and_receive(arg)
	s.close()
	return parser.parse(ret)