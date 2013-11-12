import nms.sshconnection as sshconnection

class Connector():
	def __init__(self):
		self.s = None
		self.execPasswd = '1234'


	def demo_connectDevice(self, hostname, username, password, port = 22):
		self.s = sshconnection.SSHConnection(hostname, username, password, port)
		self.s.connect()
		
	def demo_closeDevice(self):
		self.s.close()

	def demo_shutdown(self, interface):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(self.execPasswd, delay=0.1)
		self.s.send_and_receive('configure terminal', delay=0.1)
		self.s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
		ret = self.s.send_and_receive('shutdown', delay=0.1)
		self.s.send_and_receive('end\ndisable')
		return ret

	def demo_noshutdown(self, interface):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(self.execPasswd, delay=0.1)
		self.s.send_and_receive('configure terminal', delay=0.1)
		self.s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
		ret = self.s.send_and_receive('no shutdown', delay=0.1)
		self.s.send_and_receive('end\ndisable')
		return ret

	def demo_interfaceip(self, interface, ip, subnet):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(self.execPasswd, delay=0.1)
		self.s.send_and_receive('configure terminal', delay=0.1)
		self.s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
		ret = self.s.send_and_receive('ip address' + ip + ' ' + subnet, delay=0.1)
		self.s.send_and_receive('end\ndisable')
		return ret

	def demo_interfacedescription(self, interface, description):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(self.execPasswd, delay=0.1)
		self.s.send_and_receive('configure terminal', delay=0.1)
		self.s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
		ret = self.s.send_and_receive('description ' + description, delay=0.1)
		self.s.send_and_receive('end\ndisable')
		return ret

	def demo_showipinterfacebrief(self):
		self.s.send_and_receive('enable', delay=0.1)
		self.s.send_and_receive(self.execPasswd, delay=0.1)
		ret = self.s.send_and_receive('show ip interface brief', delay=0.1)
		self.s.send_and_receive('disable')
		return ret
