"""
This module contains XML parsing routines and regex implementation for the XML-specified parsing rules.

Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option) 
any later version.
"""

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
		"""Splits text by the specified delimiter and then passes
		it to the regex module.
		
		Keyword arguments:
		text -- The input string to parse
		
		Return value:
		List of strings
		"""
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
	"""Given an XML element containing a number of command arguments,
	return a list of strings containing these commands.
	
	Keyword arguments:
	element      -- A command XML element
	interface    -- The interface name to replace %if% tags with
	privPassword -- The password to use when a "privpasswd" type is encountered
	
	Return value:
	List of strings
	"""
	ret = []
	
	for i in range(0, len(element.getchildren())):
		for c in element.getchildren():
			if int(c.get('position')) == i:
				if c.get('type') == 'plaintext':
					if c.text == None:
						ret.append('')
					else:
						ret.append(c.text.replace('%if%', interface))
				elif c.get('type') == 'privpasswd':
					ret.append(privPassword)
				else:
					tb = sys.exc_info()[2]
					raise ValueError('Unsupported argElement type').with_traceback(tb)
	return ret

def __getParser__(element):
	"""Obtains a RegexWrapper object given a returnParsing XML element
	
	Keyword arguments:
	element -- A returnParsing XML element
	
	Return value:
	nms.xmlparser.RegexWrapper object	
	"""
	if element.tag != 'returnParsing':
		return None
	if element.get('type') != 'regex':
		tb = sys.exc_info()[2]
		raise ValueError('Unsupported returnParsing type').with_traceback(tb)
	delimiter = element.get('delimiter')
	regex = element.text
	return RegexWrapper(regex, delimiter)

def __addItemSingle__(e, od, privPassword):
	"""Given a task XML element, add its information to the OrderedDict
	
	Keyword arguments:
	e            -- XML task element
	od           -- collections.OrderedDict object
	privPassword -- Privileged-mode password
	
	Return value:
	None
	"""
	for child in e.getchildren():
			if child.tag == 'command':
				cmd = child
				if child.get('userArgs') != None:
					uargs = child.get('userArgs').split(':')
				else:
					uargs = []
			elif child.tag == 'returnParsing':
				rp = child
	od['i:' + e.get('name')] = (uargs, __getCommand__(cmd, privPassword=privPassword), __getParser__(rp))

def __addItemPerInterface__(e, od, interfaces, privPassword):
	"""Given a task XML element, add its information to the OrderedDict once per interface
	
	Keyword arguments:
	e            -- XML task element
	od           -- collections.OrderedDict object
	interfaces   -- List of interface names
	privPassword -- Privileged-mode password
	
	Return value:
	None
	"""
	for interface in interfaces:
		name = e.get('name').replace('%if%', interface)
		for child in e.getchildren():
			if child.tag == 'command':
				cmd = child
				if child.get('userArgs') != None:
					uargs = child.get('userArgs').split(':')
				else:
					uargs = []
			elif child.tag == 'returnParsing':
				rp = child
		od['i:' + name] = (uargs, __getCommand__(cmd, interface=interface, privPassword=privPassword), __getParser__(rp))

def __addCategory__(e, od, interfaces, privPassword):
	"""Given a category XML element, create an OrderedDict and fill it with the categories content
	
	Keyword arguments:
	e            -- XML category element
	od           -- collections.OrderedDict object
	interfaces   -- List of interface names
	privPassword -- Privileged-mode password
	
	Return value:
	None	
	"""
	od['c:' + e.get('name')] = OrderedDict()
	for child in e.getchildren():
		if child.tag == 'category':
			__addCategory__(child, od['c:' + e.get('name')], interfaces=interfaces, privPassword=privPassword)
		elif child.tag == 'item':
			if child.get('type') == 'per-interface':
				__addItemPerInterface__(child, od['c:' + e.get('name')], interfaces=interfaces, privPassword=privPassword)
			elif child.get('type') == 'single':
				__addItemSingle__(child, od['c:' + e.get('name')], privPassword=privPassword)

def removeXmlStruct(location):
	"""Removes an XML structure from the cache
	
	Keyword arguments:
	device -- The device to remove the XML structure for
	
	Return value:
	None	
	"""
	global cacheLock
	global cache
	cacheLock.acquire()
	if location in cache.keys():
		del cache[location]
	cacheLock.release()
				
def get_xml_struct(filepath):
	"""Given a filepath, return its XML structure
	
	Keyword arguments:
	filepath -- The location of the XML file
	
	Return value:
	ElementTree root of the XML file	
	"""
	global cacheLock
	global cache

	cacheLock.acquire()
	try:
		if not filepath in cache.keys():
			cache[filepath] = ET.parse(filepath).getroot()
		xml_struct = cache[filepath]
		return xml_struct
	except:
		raise
	finally:
		cacheLock.release()

def getDeviceInfo(root):
	"""Given the root of the XML structure, return its deviceInfo
	
	Keyword arguments:
	root -- Root of the XML structure
	
	Return value:
	Tuple of three strings
	"""
	for child in root.getchildren():
		if child.tag == 'deviceInfo':
			e = child
	return (e.get('type'), e.get('vendor'), e.get('model'))

def getSupportedOperatingSystems(root):
	"""Given the root of the XML structure, return its OS info
	
	Keyword arguments:
	root -- Root of the XML structure
	
	Return value:
	List of strings
	"""
	for child in root.getchildren():
		if child.tag == 'supportedOperatingSystems':
			e = child
	ret = []
	for c in e.getchildren():
		ret.append(c.get('name'))
	return ret

def getInterfaceQuery(root):
	"""Given the root of the XML structure, return its interface query
	
	Keyword arguments:
	root -- Root of the XML structure
	
	Return value:
	2-tuple of a commandlist and an nms.xmlparser.RegexWrapper object.
	"""
	for child in root.getchildren():
		if child.tag == 'interfaceQuery':
			e = child
	for child in e.getchildren():
		if child.tag == 'command':
			command = __getCommand__(child)
		elif child.tag == 'returnParsing':
			parser = __getParser__(child)
	return (command, parser)

def removeTaskCache(root):
	"""Given the root of the XML strucuture, remove the task OrderedDict from the cache
	
	Keyword arguments:
	root -- Root of the XML structure
	
	Return value:
	None
	"""
	global taskcacheLock
	global taskcache
	taskcacheLock.acquire()
	if root in taskcache.keys():
		del taskcache[root]
	taskcacheLock.release()

def getAvailableTasks(root, interfaces=[], privPassword=''):
	"""Given the root of the XML structure, return an OrderedDict containing all tasks for a device
	
	Keyword arguments:
	root         -- Root of the XML structure
	interfaces   -- List of available interfaces
	privPassword -- Privileged-mode password
	
	Return value:
	collections.OrderedDict object
	"""
	global taskcacheLock
	global taskcache
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
		return ret
	except:
		raise
	finally:
		taskcacheLock.release()

def __addToHTML__(curpath, od, id):
	"""Given a path to traverse the OrderedDict and a device_id, traverse the dictionary and translate it to HTML
	
	Keyword arguments:
	curpath -- The path that still needs to be traversed (String)
	od      -- collections.OrderedDict object
	id      -- Numeric representation of the device
	
	Return value:
	String
	"""
	s = ''
	for key in od.keys():
		if key.startswith('c:'):
			s += '<li>%s</li>\n<ul>\n' % key[2:]
			if curpath == '':
				s += __addToHTML__(key, od[key], id)
			else:
				s += __addToHTML__(curpath + '|' + key, od[key], id)
			s += '</ul>\n'
		elif key.startswith('i:'):
			url = reverse('nms:device_command_handler', kwargs={'device_id_request':id})
			uargs = ''
			for uarg in od[key][0]:
				uargs += '&arg:' + uarg
			s += '<li><a id="%s" href="%s?command=%s%s" onclick="muteurl(\'%s\');">%s</a></li>' % (curpath + '|' + key, url, curpath + '|' + key, uargs, curpath + '|' + key, key[2:])
	return s

def getAvailableTasksHtml(root, id, interfaces=[], privPassword=''):
	"""Given the root of the XML structure and device information, returns the HTML for performing tasks on the device
	
	Keyword arguments:
	root         -- Root of the XML structure
	id           -- Numeric representation of the device
	interfaces   -- List of interface names available
	privPassword -- Privileged-mode password for the device
	
	Return value:
	String
	"""
	od = getAvailableTasks(root, interfaces, privPassword)
	s = '<ul>\n'
	s += __addToHTML__('', od, id)
	s += '</ul>\n'
	return s
