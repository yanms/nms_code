import xml.etree.ElementTree as ET
from multiprocessing import Lock
from collections import OrderedDict
import copy, sys, re

cacheLock = Lock()
interfaceMapLock = Lock()
cache = {}
interfaceMap = {}

class RegexWrapper():
	def __init__(self, regex, delimiter):
		self.delimiter = delimiter.encode('utf_8').decode('unicode-escape')
		self.regex = regex.encode('utf_8').decode('unicode-escape')
	
	def parse(self, text):
		text = text.split(self.delimiter)
		ret = []
		for line in text:
			matches = re.findall(self.regex, line)
			for match in matches:
				ret.append(match)
		return ret

def __getCommand__(element, interface = None):
	ret = []
	for i in range(0, len(element.getchildren())):
		for c in element.getchildren():
			if int(c.get('position')) == i:
				if c.get('type') == 'plaintext':
					ret.append(c.text)
				elif c.get('type') == 'interface':
					ret.append(interface)
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
	delimiter = element.get('interfaceDelimiter')
	regex = element.text
	return RegexWrapper(regex, delimiter)

def get_xml_struct(filepath):
	global lock
	global cache

	cacheLock.acquire()
	if not filepath in cache.keys():
		cache[filepath] = ET.parse(filepath).getroot()
	xml_struct = copy.deepcopy(cache[filepath])
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

def __addItemSingle__(e, od):
	od['i:' + e.get('name')] = (__getCommand__(e), __getParser__(e))

def __addItemPerInterface__(e, od, interfaces):
	for interface in interfaces:
		name = e.get('name')
		name.replace('%if%', interface)
		od['i:' + name] = (__getCommand__(e, interface), __getParser__(e))

def __addCategory__(e, od, interfaces):
	od['c:' + e.get('name')] = OrderedDict()
	for child in e.getchildren():
		if child.tag == 'category':
			__addCategory__(child, od['c:' + e.get('name')])
		elif child.tag == 'item':
			if child.get('type') == 'per-interface':
				__addItemPerInterface__(child, od['c:' + e.get('name')], interfaces)
			elif child.get('type') == 'single':
				__addItemSingle__(child, od['c:' + e.get('name')])

def getAvailableTasks(root, interfaces):
	for child in root.getchildren():
		if child.tag == 'configurationItems':
			e = child
	ret = OrderedDict()
	for child in e.getchildren():
		if child.tag == 'category':
			__addCategory__(child, ret, interfaces)
		elif child.tag == 'item':
			if child.get('type') == 'per-interface':
				__addItemPerInterface__(child, ret, interfaces)
			elif child.get('type') == 'single':
				__addItemSingle__(child, ret)