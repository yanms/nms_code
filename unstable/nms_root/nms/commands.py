import nms.sshconnection as sshconnection

s = None
execPasswd = '1234'


def demo_connectDevice(hostname, username, password, port = 22):
	s = sshconnection.SSHConnection(hostname, username, password, port)
	s.connect()
	
def demo_closeDevice():
	s.close()

def demo_shutdown(interface):
	s.send_and_receive('enable', delay=0.1)
	s.send_and_receive(execPasswd, delay=0.1)
	s.send_and_receive('configure terminal', delay=0.1)
	s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
	ret = s.send_and_receive('shutdown', delay=0.1)
	s.send_and_receive('end\nend\ndisable')
	return ret

def demo_noshutdown(interface):
	s.send_and_receive('enable', delay=0.1)
	s.send_and_receive(execPasswd, delay=0.1)
	s.send_and_receive('configure terminal', delay=0.1)
	s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
	ret = s.send_and_receive('no shutdown', delay=0.1)
	s.send_and_receive('end\nend\ndisable')
	return ret

def demo_interfaceip(interface, ip):
	s.send_and_receive('enable', delay=0.1)
	s.send_and_receive(execPasswd, delay=0.1)
	s.send_and_receive('configure terminal', delay=0.1)
	s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
	ret = s.send_and_receive('ip ' + ip, delay=0.1)
	s.send_and_receive('end\nend\ndisable')
	return ret

def demo_interfacedescription(interface, description):
	s.send_and_receive('enable', delay=0.1)
	s.send_and_receive(execPasswd, delay=0.1)
	s.send_and_receive('configure terminal', delay=0.1)
	s.send_and_receive('interface FastEthernet ' + interface, delay=0.1)
	ret = s.send_and_receive('description ' + description, delay=0.1)
	s.send_and_receive('end\nend\ndisable')
	return ret

def demo_showipinterfacebrief():
	s.send_and_receive('enable', delay=0.1)
	s.send_and_receive(execPasswd, delay=0.1)
	ret = s.send_and_receive('show ip interface brief', delay=0.1)
	s.send_and_receive('disable')
	return ret
