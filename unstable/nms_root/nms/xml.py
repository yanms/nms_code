import xml.etree.ElementTree as ET
from multiprocessing import Lock
import copy
#xml_struct = get_xml_struct(device)

lock = Lock()
cache = {}

def get_xml_struct(device):
	global lock
	global cache

	lock.acquire()
	if not device in cache.keys():
		cache[device] = ET.parse(device).getroot()
	xml_struct = copy.deepcopy(cache[device])
	lock.release()
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

def __getCommand__(element):
	ret = []
	for i in range(0, len(element.getchildren())):
		for c in element.getchildren():
			if int(c.get('position')) == i:
				ret.append(c.text)
	return ret