import xml.etree.ElementTree as ET
from multiprocessing import Lock
from collections import OrderedDict
import sys, re
from django.core.urlresolvers import reverse

cacheLock = Lock()
cache = {}

taskcacheLock = Lock()
taskcache = {}


class RegexWrapper():
	def __init__(self, regex, delimiter):
		self.delimiter = delimiter.encode('utf_8').decode('unicode-escape')
		self.regex = regex.encode('utf_8').decode('unicode-escape')
	
	def parse(self, text):
		if type(text) == type(bytes()):
			text = text.decode()
		text = text.split(self.delimiter)
		ret = []
		for line in text:
			matches = re.findall(self.regex, line)
			for match in matches:
				ret.append(match)
		return ret

def __getCommand__(element, interface = '', privPassword = ''):
	ret = []
	for i in range(0, len(element.getchildren())):
		for c in element.getchildren():
			if int(c.get('position')) == i:
				if c.get('type') == 'plaintext':
					ret.append(c.text.replace('%if%', interface))
				elif c.get('type') == 'privpasswd':
					ret.append(privPassword)
				else:
					tb = sys.exc_info()[2]
					raise ValueError('Unsupported argElement type').with_traceback(tb)
	return ret

def __getParser__(element):
	if element.tag != 'returnParsing':
		return None
	if element.get('type') != 'regex':
		tb = sys.exc_info()[2]
		raise ValueError('Unsupported returnParsing type').with_traceback(tb)
	delimiter = element.get('delimiter')
	regex = element.text
	return RegexWrapper(regex, delimiter)

def __addItemSingle__(e, od, privPassword):
	for child in e.getchildren():
			if child.tag == 'command':
				cmd = child
			elif child.tag == 'returnParsing':
				rp = child
	od['i:' + e.get('name')] = (__getCommand__(cmd, privPassword=privPassword), __getParser__(rp))

def __addItemPerInterface__(e, od, interfaces, privPassword):
	for interface in interfaces:
		name = e.get('name').replace('%if%', interface)
		for child in e.getchildren():
			if child.tag == 'command':
				cmd = child
			elif child.tag == 'returnParsing':
				rp = child
		od['i:' + name] = (__getCommand__(cmd, interface=interface, privPassword=privPassword), __getParser__(rp))

def __addCategory__(e, od, interfaces, privPassword):
	od['c:' + e.get('name')] = OrderedDict()
	for child in e.getchildren():
		if child.tag == 'category':
			__addCategory__(child, od['c:' + e.get('name')], interfaces=interfaces, privPassword=privPassword)
		elif child.tag == 'item':
			if child.get('type') == 'per-interface':
				__addItemPerInterface__(child, od['c:' + e.get('name')], interfaces=interfaces, privPassword=privPassword)
			elif child.get('type') == 'single':
				__addItemSingle__(child, od['c:' + e.get('name')], privPassword=privPassword)

def get_xml_struct(filepath):
	global lock
	global cache

	cacheLock.acquire()
	try:
		if not filepath in cache.keys():
			cache[filepath] = ET.parse(filepath).getroot()
		xml_struct = cache[filepath]
	except:
		raise
	finally:
		cacheLock.release()
	return xml_struct

def getDeviceInfo(root):
	for child in root.getchildren():
		if child.tag == 'deviceInfo':
			e = child
	return (e.get('type'), e.get('vendor'), e.get('model'))

def getSupportedOperatingSystems(root):
	for child in root.getchildren():
		if child.tag == 'supportedOperatingSystems':
			e = child
	ret = []
	for c in e.getchildren():
		ret.append(c.get('name'))
	return ret

def getInterfaceQuery(root):
	for child in root.getchildren():
		if child.tag == 'interfaceQuery':
			e = child
	for child in e.getchildren():
		if child.tag == 'command':
			command = __getCommand__(child)
		elif child.tag == 'returnParsing':
			parser = __getParser__(child)
	return (command, parser)

def getAvailableTasks(root, interfaces=[], privPassword=''):
	#locks might not be required here, as the struct is used as read-only mostly
	taskcacheLock.acquire()
	try:
		if root in taskcache.keys():
			ret = taskcache[root]
			return ret

		for child in root.getchildren():
			if child.tag == 'configurationItems':
				e = child
		ret = OrderedDict()
		for child in e.getchildren():
			if child.tag == 'category':
				__addCategory__(child, ret, interfaces=interfaces, privPassword=privPassword)
			elif child.tag == 'item':
				if child.get('type') == 'per-interface':
					__addItemPerInterface__(child, ret,interfaces=interfaces, privPassword=privPassword)
				elif child.get('type') == 'single':
					__addItemSingle__(child, ret, privPassword=privPassword)
		taskcache[root] = ret
	except:
		raise
	finally:
		taskcacheLock.release()
	return ret

def __addToHTML__(curpath, od, id):
	s = ''
	for key in od.keys():
		if key.startswith('c:'):
			s += '<li>%s</li>\n<ul>\n' % key[2:]
			s += __addToHTML__(curpath + '#' + key, od[key], id)
			s += '</ul>\n'
		elif key.startswith('i:'):
			url = reverse('nms:device_command_handler', kwargs={'device_id_request':id})
			s += '<li><a href="%s/?command=%s">%s</a></li>' % (url, curpath + '#' + key, key[2:])
	return s

def getAvailableTasksHtml(root, id, interfaces=[], privPassword=''):
	od = getAvailableTasks(root, interfaces, privPassword)
	s = '<ul>\n'
	s += __addToHTML__('', od, id)
	return s
