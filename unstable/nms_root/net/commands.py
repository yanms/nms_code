import nms.sshconnection as sshconncetion

class Connection(object):

	def __init__(self):
		self.s = None
		self.execPasswd = '1234'

	def demo_connectDevice(hostname, username, password, port = 22):
		self.s = sshconnection.SSHConnection(hostname, username, password, port)
		self.s.connect()
		
	def demo_closeDevice():
		self.s.close()

	def demo_shutdown(interface):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(execPasswd, delay=0.1)
		self.s.send_and_receive('configure terminal', delay=0.1)
		self.s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
		ret = self.s.send_and_receive('shutdown', delay=0.1)
		self.s.send_and_receive('end\nend\ndisable')
		return ret

	def demo_noshutdown(interface):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(execPasswd, delay=0.1)
		self.s.send_and_receive('configure terminal', delay=0.1)
		self.s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
		ret = self.s.send_and_receive('no shutdown', delay=0.1)
		self.s.send_and_receive('end\nend\ndisable')
		return ret

	def demo_interfaceip(interface, ip):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(execPasswd, delay=0.1)
		self.s.send_and_receive('configure terminal', delay=0.1)
		self.s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
		ret = self.s.send_and_receive('ip ' + ip, delay=0.1)
		self.s.send_and_receive('end\nend\ndisable')
		return ret

	def demo_interfacedescription(interface, description):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(execPasswd, delay=0.1)
		self.s.send_and_receive('configure terminal', delay=0.1)
		self.s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
		ret = self.s.send_and_receive('description ' + description, delay=0.1)
		self.s.send_and_receive('end\nend\ndisable')
		return ret

	def demo_showipinterfacebrief():
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(execPasswd, delay=0.1)
		ret = self.s.send_and_receive('show ip interface brief', delay=0.1)
		self.s.send_and_receive('disable')
		return ret