"""
This module is used to obtain or store passwords for devices, as well as the master password used for encryption.

Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option) 
any later version.
"""

from Crypto.Cipher import AES
from Crypto import Random
import base64
import ctypes
import nms
import os

#Handle to the C library used to access shared memory.
lib = None

class AESCipher:
	def __init__(self, key):
		self.key = key
		self.BS = 16
		self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
		self.unpad = lambda s: s[0:-s[-1]]

	def encrypt(self, raw):
		raw = self.pad(raw)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv+cipher.encrypt(raw))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(enc[16:]))

def __initSHMLib__():
	"""Put the ctypes library handle for the shared memory .so in the global lib variable
	
	Return value:
	None
	"""
	global lib
	path = os.path.abspath(os.path.dirname(nms.__file__))
	lib = ctypes.cdll.LoadLibrary(path + '/c/shmlib.so')
	lib.store_password.restype = None
	lib.get_password.restype = ctypes.c_char_p

def storeMasterPassword(password):
	"""Writes the master password to shared memory
	
	Keyword arguments:
	password -- A 16-character password used as half of the AES encryption and decryption
	
	Return value:
	Integer
	"""
	global lib
	if lib == None:
		__initSHMLib__()

	if len(password) != 16:
		return -1
	lib.store_password(password.encode(), 16)
	return 0

def hasMasterPassword():
	"""Returns True if the master password has been set, False otherwise
	
	Return value:
	Boolean	
	"""
	global lib
	#if lib == None:
	__initSHMLib__()

	if len(lib.get_password()) == 16:
		return True
	return False

def storeEnablePassword(device, password):
	"""Encrypts and stores the privileged-mode password for a device
	
	Keyword arguments:
	device   -- The device to store the password for
	password -- The password
	
	Return value:
	None
	"""
	global lib
	if lib == None:
		__initSHMLib__()

	salt = base64.b64encode(Random.new().read(16))[:16].decode()
	cipher = AESCipher(lib.get_password().decode() + salt)
	device.password_enable = salt + '$' + cipher.encrypt(password).decode()
	device.save()

def storeRemotePassword(device, password):
	"""Encrypts and stores the login password for a device
	
	Keyword arguments:
	device   -- The device to store the password for
	password -- The password
	
	Return value:
	None
	"""
	global lib
	if lib == None:
		__initSHMLib__()

	salt = base64.b64encode(Random.new().read(16))[:16].decode()
	cipher = AESCipher(lib.get_password().decode() + salt)
	device.password_remote = salt + '$' + cipher.encrypt(password).decode()
	device.save()

def getEnablePassword(device):
	"""Decrypts and returns the privileged-mode password for a device
	
	Keyword arguments:
	device -- The device to obtain the password for
	
	Return value:
	String
	"""
	global lib
	if lib == None:
		__initSHMLib__()

	try:
		cipher = AESCipher(lib.get_password().decode() + device.password_enable[:device.password_enable.find('$')])
		return cipher.decrypt(device.password_enable[device.password_enable.find('$')+1:])
	except:
		return b''
		

def getRemotePassword(device):
	"""Decrypts and returns the login password for a device
	
	Keyword arguments:
	device -- The device to obtain the password for
	
	Return value:
	String	
	"""
	global lib
	if lib == None:
		__initSHMLib__()

	try:
		cipher = AESCipher(lib.get_password().decode() + device.password_remote[:device.password_remote.find('$')])
		return cipher.decrypt(device.password_remote[device.password_remote.find('$')+1:])
	except:
		return b''