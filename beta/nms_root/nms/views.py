"""
This module contains all django views for this app

Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option) 
any later version.
"""

import nms
from nms import commands
from nms import xmlparser
from nms import passwordstore
from nms.models import *

import traceback
import os as os_library
from xml.etree import ElementTree
from subprocess import call

import django.db.models as django_exception
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import User, Permission, Group
from django.contrib.contenttypes.models import ContentType
from django.contrib.sessions.models import Session
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
from django.shortcuts import get_object_or_404, render
from django.template import RequestContext
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect

@login_required
def index(request):
	return render(request, 'nms/index.html', {'request':request})

def install(request):
	"""Creates several permissions, sets the hostname for the server
	and calls make on the nms/c/ directory for the shmlib.so
	
	Location: /install
	"""
	#Check if the installation is already completed
	if Settings.objects.filter(known_name='install complete').exists():
		if Settings.objects.filter(known_name='install complete', known_boolean=True).exists():
			return HttpResponse('Installation already finished.')
	#Do the installation
	else:
		#request.method == 'POST' -> The hostname form was submitted, we can install
		if request.method == 'POST':
			if not 'hostname' in request.POST:
				return HttpResponse('Missing hostname')
			
			#Set up all permissions
			content_type = ContentType.objects.get_for_model(User)
			list_user, created = Permission.objects.get_or_create(codename='list_user', name='Can list users', content_type=content_type)
			content_type = ContentType.objects.get_for_model(Group)
			list_group, created = Permission.objects.get_or_create(codename='list_group', name='Can list (dev/usr) groups', content_type=content_type)
			content_type = ContentType.objects.get_for_model(Devices)
			manage_devices, created = Permission.objects.get_or_create(codename='manage_devices', name='Can manage devices (perform action)', content_type=content_type)
			content_type = ContentType.objects.get_for_model(Devices)
			list_devices, created = Permission.objects.get_or_create(codename='list_devices', name='Can list devices', content_type=content_type)
			
			group, created = Group.objects.get_or_create(name='usr:staff')
			add_group = Permission.objects.get(codename='add_group')
			change_group = Permission.objects.get(codename='change_group')
			delete_group = Permission.objects.get(codename='delete_group')
			add_devices = Permission.objects.get(codename='add_devices')
			delete_devices = Permission.objects.get(codename='delete_devices')
			add_gen_dev = Permission.objects.get(codename='add_gen_dev')
			change_gen_dev = Permission.objects.get(codename='change_gen_dev')
			delete_gen_dev = Permission.objects.get(codename='delete_gen_dev')
			group.permissions = [add_group, change_group, delete_group, list_group, add_devices, delete_devices, add_gen_dev, change_gen_dev, delete_gen_dev]
			
			group, created = Group.objects.get_or_create(name='usr:admin')
			add_user = Permission.objects.get(codename='add_user')
			change_user = Permission.objects.get(codename='change_user')
			delete_user = Permission.objects.get(codename='delete_user')
			group.permissions = [add_user, change_user, delete_user, list_user, add_group, change_group, delete_group, list_group, add_devices, delete_devices, add_gen_dev, change_gen_dev, delete_gen_dev]
			Settings.objects.create(known_id=1, known_name='install complete', known_boolean=True)
			Settings.objects.create(known_id=2, known_name='hostname', string=request.POST['hostname'])
			
			#Make the shmlib C library for shared memory segments
			path = os_library.path.abspath(os_library.path.dirname(nms.__file__))
			call(['make', path + '/c/'])
			return HttpResponse('Finished installing NMS.')
		#request.method != 'POST' -> Display the form to fill in the hostname
		else:
			return render(request, 'nms/install.html', {'request':request})

@login_required
def acl(request):
	"""Main ACL page
	
	Location: /acl
	"""
	#Counts are used in all ACL pages for the menu-numbers indicating the number of group, user and device objects
	group_count = Group.objects.count()
	user_count = User.objects.count()
	devices_count = Devices.objects.count()
	return render(request, 'nms/acl.html', {'request':request, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count})

@login_required
def acl_groups(request):
	"""Main ACL groups page
	
	Location: /acl/groups
	"""
	group_count = Group.objects.count()
	user_count = User.objects.count()
	devices_count = Devices.objects.count()
	if request.user.has_perm('auth.list_user') or request.user.has_perm('auth.add_group') or request.user.has_perm('auth.change_group') or request.user.has_perm('auth.delete_group'):
		user_perm = request.user.has_perm('auth.list_group')
		dev_groups = Group.objects.filter(name__startswith='dev:')
		usr_groups = Group.objects.filter(name__startswith='usr:')
		return render(request, 'nms/acl_groups.html', {'user_perm': user_perm, 'dev_groups': dev_groups, 'usr_groups': usr_groups, 'request':request, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count})
	else:
		messages.error(request, 'You do not have the right permissions to access this page')
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_user(request):
	"""Main ACL users page
	
	Location: /acl/users
	"""
	group_count = Group.objects.count()
	user_count = User.objects.count()
	devices_count = Devices.objects.count()
	if request.user.has_perm('auth.list_user') or request.user.has_perm('auth.add_user') or request.user.has_perm('auth.delete_user') or request.user.has_perm('auth.change_user'):
		user_list = User.objects.all() 
		return render(request, 'nms/acl_users.html', {'user_list': user_list,'request':request, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count})
	else:
		messages.error(request, 'You do not have the right permissions to access this page')
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_user_add(request):
	"""User add page
	
	Location: /acl/users/add
	"""
	group_count = Group.objects.count()
	user_count = User.objects.count()
	devices_count = Devices.objects.count()
	if request.user.has_perm('auth.add_user'):
		return render(request, 'nms/acl_user_add.html', {'request':request, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count})
	else:
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_user_add_handler(request):
	"""User add handler. Redirects when done.
	
	Location: /acl/users/add/handler
	"""
	if request.user.has_perm('auth.add_user'):
		if request.method == 'POST':
			try:
				username = request.POST['username']
				firstname = request.POST['firstname']
				lastname = request.POST['surname']
				email = request.POST['emailaddress']
				password = request.POST['password']
				password_check = request.POST['password2']
				#Check if the user already exists
				if User.objects.filter(username=username).exists():
					messages.error(request, 'User already exists.')
					return HttpResponseRedirect(reverse('nms:acl_user_add'))
				if username == '':
					messages.error(request, 'Username cannot be empty.')
					return HttpResponseRedirect(reverse('nms:acl_user_add'))
				#Check if the two passwords match and are not empty
				if password == password_check and password != '':
					#Create the player
					user = User.objects.create()
					user.username = username
					user.first_name = firstname
					user.last_name = lastname
					user.email = email
					user.set_password(password)
					user.save()
					History.objects.create(action_type='ACL: User', action='Added user', user_id=user, user_performed_task=request.user, date_time = timezone.now())
					messages.success(request, "Database updated successfully.")
					return HttpResponseRedirect(reverse('nms:acl_user_add'))
				#Password mismatch or empty
				else:
					messages.error(request, 'Password fields may not be empty.')
					return HttpResponseRedirect(reverse('nms:acl_user_add'))
			#KeyError can be raised on POST arguments not existing
			except KeyError as err:
				messages.error(request, "Not all fields are set")
				messages.error(request, err)
				return HttpResponseRedirect(reverse('nms:acl_user_add'))
		#request.method != 'POST'
		else:
			messages.error(request, "Invalid method")
			return HttpResponseRedirect(reverse('nms:acl_user_add'))
	#not request.user.has_perm('auth.add_user')
	else:
		messages.error(request, 'You do not have the right permissions to access this page')
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_user_manage(request, acl_user):
	"""User-specific manage page
	
	Location: /acl/users/\d+/manage
	"""
	group_count = Group.objects.count()
	user_count = User.objects.count()
	devices_count = Devices.objects.count()
	user_obj = get_object_or_404(User, pk=acl_user)
	if request.user.has_perm('auth.change_user') and user_obj.username != 'root':
		groups = Group.objects.all()
		is_active_check = 'checked' if user_obj.is_active else ''
		return render(request, 'nms/acl_user_manage.html', {'user_obj': user_obj, 'groups': groups, 'request':request, 'is_active_check': is_active_check, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count})
	else:
		messages.error(request, 'You do not have the right permissions to access this page')
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_user_manage_handler(request, acl_user):
	"""User-specific manage handler. This view redirects when done.
	
	Location: /acl/users/\d+/manage/handler
	"""
	if request.user.has_perm('auth.change_user'):
		user_obj = get_object_or_404(User, pk=acl_user)
		if request.method == 'POST':
			try:
				first_name = request.POST['first_name']
				last_name = request.POST['last_name']
				email = request.POST['email']
				if 'is_active' in request.POST:
					is_active = request.POST['is_active']
				else:
					is_active=False
				password = request.POST['password']
				password2 = request.POST['password2']
				if password == password2:
					user_obj.first_name = first_name
					user_obj.last_name = last_name
					user_obj.email = email
					user_obj.is_active = is_active
					if password != '':
						user_obj.set_password(password)
					user_obj.save()
					messages.success(request, "Database successfully updated.")
					History.objects.create(action_type='ACL: change user rights', action='Change user settings', user_performed_task=request.user, user_id=user_obj, date_time=timezone.now())
					return HttpResponseRedirect(reverse('nms:acl_user_manage', args=(acl_user,)))
				else:
				   messages.error(request, "Passwords are not the same")
				   return HttpResponseRedirect(reverse('nms:acl_user_manage', args=(acl_user,))) 
			except KeyError:
				messages.error(request, "Not all fields are set")
				return HttpResponseRedirect(reverse('nms:acl_user_manage', args=(acl_user,))) 
		messages.error(request, "Invalid method")
		return HttpResponseRedirect(reverse('nms:acl_user_manage', args=(acl_user,))) 
	else:
		messages.error(request, 'You do not have the right permissions to access this page')
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_device(request):
	"""Main ACL devices page
	
	Location: /acl/devices
	"""
	group_count = Group.objects.count()
	user_count = User.objects.count()
	devices_count = Devices.objects.count()
	if request.user.has_perm('nms.add_devices') or request.user.has_perm('nms.delete_devices') or request.user.has_perm('auth.list_group'):
		devices = Devices.objects.all() 
		return render(request, 'nms/acl_devices.html', {'devices': devices,'request':request, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count})
	else:
		messages.error(request, 'You do not have the right permissions to access this page')
		return HttpResponseRedirect(reverse('nms:acl'))


@login_required
def acl_device_manage(request, acl_id):
	"""ACL device-specific manage page
	
	Location: /acl/devices/\d+/manage
	"""
	group_count = Group.objects.count()
	user_count = User.objects.count()
	devices_count = Devices.objects.count()
	if request.user.has_perm('auth.list_group'):
		#The object of the device we're managing here
		dev_obj = get_object_or_404(Devices, pk=acl_id)
		#All available device groups
		dev_groups = Group.objects.filter(name__startswith='dev:')
		#The device groups that will appear with checkboxes already ticked
		checked = [dev_group.gid for dev_group in Dev_group.objects.filter(devid=dev_obj)]
		return render(request, 'nms/acl_devices_manage.html', {'dev_obj': dev_obj, 'dev_groups': dev_groups, 'checked': checked, 'request':request, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count})
	else:
		messages.error(request, 'You do not have the right permissions to access this page')
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_handler(request, acl_id):
	"""ACL handler, all requests for changing user/device groups are handled here. This view redirects when done.
	
	Location: /acl/\d+/manage
	"""
	if request.method == 'POST':
		try:
			task = request.POST['task']
			if task == 'usr_group_update':
				if request.user.has_perm('auth.list_group'):
					user_obj = get_object_or_404(User, pk=acl_id)
					groupnames = request.POST.getlist('groups')
					user_obj.groups = []
					for groupname in groupnames:
						group = get_object_or_404(Group, name=groupname)
						user_obj.groups.add(group)
						History.objects.create(action_type = 'ACL: Modified user groups', user_id = user_obj, user_performed_task = request.user, action='Currently assigned groups: {0}'.format(group), group_id=group, date_time = timezone.now())
					messages.success(request, 'Database updated successfully')
					return HttpResponseRedirect(reverse('nms:acl_user'))
				else:
					messages.error(request, "You don't have the right permissions")
					return HttpResponseRedirect(reverse('nms:acl'))
			elif task == 'ch_per_usr_group':
				if request.user.has_perm('auth.change_group'):
					group = get_object_or_404(Group, pk=acl_id)
					rights = request.POST.getlist('rights')
					groups_received = request.POST.getlist('groups')
					users_received = request.POST.getlist('users')
					group.permissions = []
					group.user_set.clear()
					for right in rights:
						permission = Permission.objects.get(codename=right)
						group.permissions.add(permission)
			
					for group_received in groups_received:
						group_recv = get_object_or_404(Group, pk=group_received)
						for item in group_recv.user_set.all():
							group.user_set.add(item)
					for user_received in users_received:
						user_recv = get_object_or_404(User, pk=user_received)
						group.user_set.add(user_recv)
					
					History.objects.create(action_type='ACL: Changed permission user group', action='Current permissions {0}'.format(group.permissions.all()), group_id=group, user_performed_task = request.user, date_time = timezone.now())
					History.objects.create(action_type='ACL: Changed users listed in user group', action='Current users listed in user group: {0}'.format(group.user_set.all()), group_id=group, user_performed_task = request.user, date_time = timezone.now())
					messages.success(request, 'Database updated successfully')
					return HttpResponseRedirect(reverse('nms:acl_groups_manage', args=(acl_id,)))
				else:
					messages.error(request, "You don't have the right permissions")
					return HttpResponseRedirect(reverse('nms:acl'))
		
			elif task == 'dev_group_update':
				if request.user.has_perm('auth.list_group'):
					device = get_object_or_404(Devices, pk=acl_id)
					groups = request.POST.getlist('groups')
					if Dev_group.objects.filter(devid=device).exists():
						Dev_group.objects.filter(devid=device).delete()
					for group in groups:
						group_obj = get_object_or_404(Group, pk=group)
						Dev_group.objects.get_or_create(gid=group_obj, devid=device)
						History.objects.create(action_type = 'ACL: Modified groups where device is listed', dev_id = device, user_performed_task = request.user, action='Currently assigned groups: {0}'.format(group_obj), group_id=group_obj, date_time = timezone.now())
					messages.success(request, 'Database updated successfully')
					return HttpResponseRedirect(reverse('nms:acl_device'))
				else:
					messages.error(request, "You don't have the right permissions")
					return HttpResponseRedirect(reverse('nms:acl'))	
		
			elif task == 'ch_per_dev_group':
				if request.user.has_perm('auth.change_group'):
					group = get_object_or_404(Group, pk=acl_id)
					groups_received = request.POST.getlist('groups')
					users_received = request.POST.getlist('users')
					devices = request.POST.getlist('devices')
					rights = request.POST.getlist('rights')
					group.permissions = []
					group.user_set.clear()
					if Dev_group.objects.filter(gid=group).exists():
						Dev_group.objects.filter(gid=group).delete()
					for device in devices:
						dev = Devices.objects.get(pk=device)
						Dev_group.objects.get_or_create(gid=group, devid=dev)
					for right in rights:
						right += '_devices'
						permission = Permission.objects.get(codename=right)
						group.permissions.add(permission)
					for group_received in groups_received:
						group_recv = get_object_or_404(Group, pk=group_received)
						for item in group_recv.user_set.all():
							group.user_set.add(item)
					for user_received in users_received:
						user_recv = get_object_or_404(User, pk=user_received)
						group.user_set.add(user_recv)
					History.objects.create(action_type='ACL: Changed permission device group', action='Current permissions {0}'.format(group.permissions.all()), group_id=group, user_performed_task = request.user, date_time = timezone.now())
					History.objects.create(action_type='ACL: Changed users listed in device group', action='Current users listed in device group: {0}'.format(group.user_set.all()), group_id = group, user_performed_task = request.user, date_time = timezone.now())
					messages.success(request, 'Database updated successfully')
					return HttpResponseRedirect(reverse('nms:acl_groups_manage', args=(acl_id,)))
				else:
					messages.error(request, "You don't have the right permissions")
					return HttpResponseRedirect(reverse('nms:acl'))
			
		except:
			messages.error(request, 'Not all required fields are set')
			messages.error(request, traceback.format_exc()) #debug code
			messages.error(request, list(request.POST.items())) #debug code
			return HttpResponseRedirect(reverse('nms:acl_groups'))
	else:
		messages.error(request, 'Not a POST method')
		return HttpResponseRedirect(reverse('nms:index'))


@login_required
def acl_groups_manage(request, acl_id):
	"""ACL group-specific manage page
	
	Location: /acl/groups/\d+/manage
	"""
	group_count = Group.objects.count()
	user_count = User.objects.count()
	devices_count = Devices.objects.count()
	if request.user.has_perm('auth.change_group'):
		#Set the default values for all variables the template needs
		group = get_object_or_404(Group, pk=acl_id)
		dev_check = True if group.name[:4] == 'dev:' else False
		groups_usr = Group.objects.filter(name__startswith='usr:')
		groups_dev = Group.objects.filter(name__startswith='dev:')
		users = User.objects.all()
		devices = None
		list_check = None
		manage_check = None
		change_check = None
		checked = None
		add_user = None
		change_user = None
		delete_user = None
		list_user = None
		add_group = None
		change_group = None
		delete_group = None
		list_group = None
		add_devices = None
		delete_devices = None
		add_gen_dev = None
		delete_gen_dev = None
		change_gen_dev = None
		#Try to set the variables
		if dev_check:
			devices = Devices.objects.all()
			checked = []
			for iter in devices:
				if Dev_group.objects.filter(devid=iter, gid=group).exists():
					checked.append(iter)
			list_check = 'checked' if group.permissions.filter(codename='list_devices').exists() else ''
			manage_check = 'checked' if group.permissions.filter(codename='manage_devices').exists() else ''
			change_check = 'checked' if group.permissions.filter(codename='change_devices').exists() else ''
		else:
			add_user = 'checked' if group.permissions.filter(codename='add_user').exists() else ''
			change_user = 'checked' if group.permissions.filter(codename='change_user').exists() else ''
			delete_user = 'checked' if group.permissions.filter(codename='delete_user').exists() else ''
			list_user = 'checked' if group.permissions.filter(codename='list_user').exists() else ''
			add_group = 'checked' if group.permissions.filter(codename='add_group').exists() else ''
			change_group = 'checked' if group.permissions.filter(codename='change_group').exists() else ''
			delete_group = 'checked' if group.permissions.filter(codename='delete_group').exists() else ''
			list_group = 'checked' if group.permissions.filter(codename='list_group').exists() else ''
			add_devices = 'checked' if group.permissions.filter(codename='add_devices').exists() else ''
			delete_devices = 'checked' if group.permissions.filter(codename='delete_devices').exists() else ''
			add_gen_dev = 'checked' if group.permissions.filter(codename='add_gen_dev').exists() else ''
			delete_gen_dev = 'checked' if group.permissions.filter(codename='delete_gen_dev').exists() else ''
			change_gen_dev = 'checked' if group.permissions.filter(codename='change_gen_dev').exists() else ''
	
	
		return render(request, 'nms/acl_groups_manage.html', {'devices': devices, 'group':group, 'list_check': list_check, 'manage_check': manage_check, 'change_check': change_check, 'checked': checked, 'dev_check': dev_check,
															'add_user': add_user, 'change_user': change_user, 'delete_user': delete_user, 'list_user': list_user, 'add_group': add_group, 'change_group': change_group, 'delete_group': delete_group, 'list_group': list_group, 'request':request, 'groups_usr': groups_usr, 'users': users, 'groups_dev': groups_dev, 'add_devices': add_devices, 'delete_devices': delete_devices, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count, 'add_gen_dev': add_gen_dev, 'delete_gen_dev': delete_gen_dev, 'change_gen_dev': change_gen_dev})
	else:
		messages.error(request, "You don't have the right permissions")
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_groups_handler(request):
	"""Handler for ACL Groups. This view redirects when done.
	
	Location: /acl/groups/handler
	"""
	if request.method == 'POST':
		if request.POST['task'] == 'usr':
			if request.user.has_perm('auth.add_user'):
				name = 'usr:'
				name += request.POST['group']
				group, checked = Group.objects.get_or_create(name=name)
				History.objects.create(group_id=group, action_type='ACL: Created group', action='Create {0} group'.format(group), date_time=timezone.now(), user_performed_task=request.user)
				messages.success(request, "Database updated succesfully")
				return HttpResponseRedirect(reverse('nms:acl_groups'))
			else:
				messages.error(request, "You don't have the right permissions")
				return HttpResponseRedirect(reverse('nms:acl'))
		elif request.POST['task'] == 'dev':
			if request.user.has_perm('nms.add_devices'):
				name = 'dev:'
				name += request.POST['group']
				group, checked = Group.objects.get_or_create(name=name)
				History.objects.create(group_id=group, action_type='ACL: Created group', action='Create {0} group'.format(group), date_time=timezone.now(), user_performed_task=request.user)
				messages.success(request, "Database updated succesfully")
				return HttpResponseRedirect(reverse('nms:acl_groups'))
			else:
				messages.error(request, "You don't have the right permissions")
				return HttpResponseRedirect(reverse('nms:acl'))
		elif request.POST['task'] == 'delete':
			if request.user.has_perm('auth.delete_group'):
				groups = request.POST.getlist('delete')
				for iter in groups:
					group = get_object_or_404(Group, pk=iter)
					if group.name == 'usr:admin' or group.name == 'usr:staff':
						messages.error(request, "Can't remove group: " + group.name)
						return HttpResponseRedirect(reverse('nms:acl_groups'))
					group.delete()  
					History.objects.create(user_performed_task=request.user, date_time=timezone.now(), action_type='ACL: Removed group', action='Removed group {0}'.format(group))
				messages.success(request, "Database updated succesfully")
				return HttpResponseRedirect(reverse('nms:acl_groups'))
			else:
				messages.error(request, "You don't have the right permissions")
				return HttpResponseRedirect(reverse('nms:acl'))
		elif request.POST['task'] == 'del_user':
			if request.user.has_perm('auth.delete_user'):
				users = request.POST.getlist('delete')
				for item in users:
					user = get_object_or_404(User, pk=item)
					if user.username == 'root':
						messages.error(request, "Can't remove user: root")
						return HttpResponseRedirect(reverse('nms:acl_user'))
					History.objects.create(user_performed_task=request.user, date_time=timezone.now(), action_type='ACL: Removed user', action='Removed user {0}'.format(user))
					[x.delete() for x in Session.objects.all() if x.get_decoded().get('_auth_user_id') == user.id]
					user.delete()
				messages.success(request, "Database updated succesfully")
				return HttpResponseRedirect(reverse('nms:acl_user'))
			else:
				messages.error(request, "You don't have the right permissions")
				return HttpResponseRedirect(reverse('nms:acl'))
		
		elif request.POST['task'] == 'del_device':
			if request.user.has_perm('nms.delete_devices'):
				devices = request.POST.getlist('delete')
				for item in devices:
					device = get_object_or_404(Devices, pk=item)
					device.dev_group_set.filter().delete()
					History.objects.create(user_performed_task=request.user, date_time=timezone.now(), action_type='ACL: Removed device', action='Removed device {0}'.format(device))
					device.delete()
				messages.success(request, "Database updated succesfully")
				return HttpResponseRedirect(reverse('nms:acl_device'))
			else:
				messages.error(request, "You don't have the right permissions")
				return HttpResponseRedirect(reverse('nms:acl'))
		
		else:
			messages.error(request, "Some fields are not set")
			return HttpResponseRedirect(reverse('nms:acl_groups'))

def register(request):
	"""Register view for registering new user accounts
	
	Location: /register
	"""
	if request.method == 'POST':
		username = request.POST['username']
		password = request.POST['password']
		password_check = request.POST['password1']
		first_name = request.POST['first_name']
		last_name = request.POST['last_name']
		email = request.POST['email']
		check_username = User.objects.filter(username=username).exists()
		if username == '':
			messages.error(request, 'Please enter a username.')
			return HttpResponseRedirect(reverse('nms:register'))
		if not check_username:
			if password == password_check and password != '':
				user = User.objects.create_user(username=username, password=password)
				user.is_active = False
				user.first_name = first_name
				user.last_name = last_name
				user.email = email
				user.save()
				History.objects.create(action_type='User', action='User created', user_performed_task=user, user_id=user, date_time=timezone.now())
				messages.success(request, 'Your accounts is created. An administrator has to activate your account')
				return HttpResponseRedirect(reverse('nms:register'))
			else:
				messages.error(request, 'Password mismatch')
				return HttpResponseRedirect(reverse('nms:register'))
		else:
			messages.error(request, 'User already exists')
			return HttpResponseRedirect(reverse('nms:register'))
	else:
		return render(request, 'nms/register.html', {'request':request})
			

def login_handler(request):
	"""The login view
	
	Location: /login
	"""
	if (request.method == 'GET' and 'next' in request.GET):
		url = request.GET['next']
		return(render(request, 'nms/login.html', {'url': url}))
	else:
		return render(request, 'nms/login.html', {'request':request})

@login_required
def devices(request):
	"""The main devices view
	
	Location: /devices
	"""
	return render(request, 'nms/devices.html', {'request':request})

@login_required
def devices_manage(request):
	"""The main manage devices page, listing all added devices
	
	Location: /devices/manage
	"""
	if request.user.has_perm('nms.list_devices'):
		user_obj = request.user
		groups = user_obj.groups.all()
		try:
			groups_list = [x for x in groups if x.permissions.filter(codename='list_devices').exists()]
			dev_group = [x.dev_group_set.all() for x in groups_list][0]
			devices = {x.devid for x in dev_group}
			devices = list(devices)
			if groups_list != [] and devices != []:
				return render(request, 'nms/devices_manage.html', {'devices': devices, 'request':request})
			elif devices == []:
				messages.error(request, "There is no device added to your device groups")
				return HttpResponseRedirect(reverse('nms:devices'))
			else:
				messages.error(request, "You are not added to any device groups with the right permission.")
				return HttpResponseRedirect(reverse('nms:index'))
		except IndexError:
			messages.error(request, "You are not added to any groups yet.")
			return HttpResponseRedirect(reverse('nms:index'))
	else:
		messages.error(request, "You don't have the right permissions")
		return HttpResponseRedirect(reverse('nms:devices'))

@login_required
def device_add(request):
	"""The view used to add new devices
	
	Location: /devices/add
	"""
	if not passwordstore.hasMasterPassword():
			return HttpResponseRedirect(reverse('nms:init') + '?next=' + reverse('nms:device_add'))
	if request.user.has_perm('nms.add_devices'):
		dev_type_view = Dev_type.objects.all()
		vendor_view = Vendor.objects.all()
		dev_model_view = Dev_model.objects.all()
		os_view = OS_dev.objects.all()
		gen_dev = Gen_dev.objects.all()
		user_dev_groups = None
		if request.user.has_perm('nms.add_devices') and request.user.has_perm('auth.list_group'):
			user_dev_groups = request.user.groups.filter(name__startswith='dev:') if request.user.groups.filter(name__startswith='dev:').exists() else None
		if request.method == 'POST':
			#return HttpResponse('Received post method.')
		
			try:
				try:
					models = Dev_model.objects.all()
					model_version_name = [[(x.model_name + ' ' + x.version if len(x.version) >= 1 else x.model_name + ' '), x.model_id] for x in models]
					model_id = [x[1] for x in model_version_name if x[0] == request.POST['selectModel']]
					if len(model_id) == 1:
						gen_dev = Gen_dev.objects.get(model_id=model_id[0], vendor_id=Vendor.objects.get(vendor_name=request.POST['selectVendor']), dev_type_id=Dev_type.objects.get(dev_type_name=request.POST['selectType']))
					else:
						messages.error(request, 'test')
						messages.error(request, list(request.POST.items()))
						messages.error(request, "Received multiple models, not unique")
						return HttpResponseRedirect(reverse('nms:device_add'))
				except:
					messages.error(request, list(request.POST.items()))
					messages.error(request, "No gendev found")
					messages.error(request, traceback.format_exc())
					return HttpResponseRedirect(reverse('nms:device_add'))
				os = get_object_or_404(OS_dev, pk=request.POST['os_dev_id'])
				pref_remote_prot = request.POST['pref_remote_prot']
				ipprot = request.POST['ipprot']
				ip_recv = request.POST['ipaddr']
				port = request.POST['port']
				login_name = request.POST['login_name']
				password_remote = request.POST['password_remote']
				password_enable = request.POST['password_enable']				
				device = Devices(gen_dev_id=gen_dev, os_dev_id=os, ip=ip_recv, pref_remote_prot=pref_remote_prot, 
				ip_version = ipprot, login_name = login_name, password_enable='', password_remote='', port=port)
				device.save()
				passwordstore.storeEnablePassword(device, password_enable)
				passwordstore.storeRemotePassword(device, password_remote)
				if 'dev_groups' in request.POST:
					dev_groups = request.POST['dev_groups']
					group_dev_add = get_object_or_404(Group, pk=dev_groups)
					Dev_group.objects.create(gid=group_dev_add, devid=device)
			except (KeyError, ValueError, NameError, UnboundLocalError):
				messages.error(request, 'Not all fields are set or an other error occured')
				return HttpResponseRedirect(reverse('nms:device_add'))
			
			History.objects.create(user_performed_task=request.user, dev_id=device, date_time=timezone.now(), action_type='Created device', action='Created device {0}'.format(device))
			messages.success(request, 'Database updated')
			return HttpResponseRedirect(reverse('nms:device_add'))
		else:
			return render(request, 'nms/devices_add.html', {'dev_type_view': dev_type_view, 'vendor_view': vendor_view,
			 'dev_model_view' : dev_model_view, 'os_view': os_view, 'gen_dev': gen_dev, 'request':request, 'user_dev_groups': user_dev_groups})
	else:
		messages.error(request, "You don't have the permission to access this page.")
		return HttpResponseRedirect(reverse('nms:devices'))
		
@login_required
def device_manager(request, device_id_request):
	"""Device-specific manage page, allowing executing tasks on the device
	
	Location: /devices/\d+/manage
	"""
	devices = get_object_or_404(Devices, pk=device_id_request)
	groups = request.user.groups.all()
	group_device = [group for group in groups if group.dev_group_set.filter(devid=devices).exists()]
	group_rights = [groups for groups in group_device if groups.permissions.filter(codename='manage_devices').exists()]
	if len(group_rights) > 0:
		if not passwordstore.hasMasterPassword():
			return HttpResponseRedirect(reverse('nms:init') + '?next=' + reverse('nms:device_manager', args=(device_id_request,)))

		if request.method == 'GET' and 'refresh' in request.GET:
			xmlparser.removeTaskCache(xmlparser.get_xml_struct(devices.gen_dev_id.file_location_id.location))
			xmlparser.removeXmlStruct(devices.gen_dev_id.file_location_id.location)
			commands.removeInterfaces(devices)
		root = xmlparser.get_xml_struct(devices.gen_dev_id.file_location_id.location)
		cmd, parser = xmlparser.getInterfaceQuery(root)
		interfaces = commands.getInterfaces(cmd, parser, devices, request.user)
		if interfaces == -1:
			messages.error(request, 'Failed to connect to device')
			return HttpResponseRedirect(reverse('nms:devices'))

		taskhtml = xmlparser.getAvailableTasksHtml(root, devices.dev_id, interfaces, passwordstore.getEnablePassword(devices))
		return render(request, 'devices_manager.html', {'devices': devices, 'taskhtml': taskhtml, 'request':request})
	else:
		messages.error(request, "You don't have the right permissions")
		return HttpResponseRedirect(reverse('nms:devices'))

@login_required
def device_modify(request, device_id_request):
	"""View for modifying device settings, such as the IP address
	
	Location: /devices/\d+/modify
	"""
	device = get_object_or_404(Devices, pk=device_id_request)
	groups = request.user.groups.all()
	group_device = [group for group in groups if group.dev_group_set.filter(devid=device).exists()]
	group_rights = [groups for groups in group_device if groups.permissions.filter(codename='change_devices').exists()]
	if len(group_rights) > 0:
		if not passwordstore.hasMasterPassword():
			return HttpResponseRedirect(reverse('nms:init') + '?next=' + reverse('nms:device_modify', args=(device_id_request,)))
		dev_type_view = Dev_type.objects.all()
		vendor_view = Vendor.objects.all()
		dev_model_view = Dev_model.objects.all()
		os_view = OS_dev.objects.all()
		gen_dev = Gen_dev.objects.all()
		if request.method == 'POST':
			#return HttpResponse('Received post method.')
			try:
				try:
					models = Dev_model.objects.all()
					model_version_name = [[(x.model_name + ' ' + x.version if len(x.version) >= 1 else x.model_name + ' '), x.model_id] for x in models]
					model_id = [x[1] for x in model_version_name if x[0] == request.POST['selectModel']]
					if len(model_id) == 1:
						device.gen_dev_id = Gen_dev.objects.get(model_id=model_id[0], vendor_id=Vendor.objects.get(vendor_name=request.POST['selectVendor']), dev_type_id=Dev_type.objects.get(dev_type_name=request.POST['selectType']))
					else:
						messages.error(request, list(request.POST.items()))
						messages.error(request, "Received multiple models, not unique")
						return HttpResponseRedirect(reverse('nms:device_modify', args=(device.dev_id,)))
				except:
					messages.error(request, "No gendev found")
					return HttpResponseRedirect(reverse('nms:device_modify', args=(device.dev_id,)))
				device.os_dev_id = get_object_or_404(OS_dev, pk=request.POST['os_dev_id'])
				device.pref_remote_prot = request.POST['pref_remote_prot']
				device.ip_version = request.POST['ipprot']
				device.ip = request.POST['ipaddr']
				device.port = request.POST['port']
				device.login_name = request.POST['login_name']
				password_remote = request.POST['password_remote']
				password_enable = request.POST['password_enable']
				device.save()
				if password_enable != '':
					passwordstore.storeEnablePassword(device, password_enable)
				if password_remote != '':
					passwordstore.storeRemotePassword(device, password_remote)
			except (KeyError, ValueError, NameError, UnboundLocalError) as err:
				messages.error(request, 'Not all fields are set or an other error occured')
				messages.error(request, err)
				print(err)
				#return HttpResponse(request.POST.items())
				return HttpResponseRedirect(reverse('nms:device_modify', args=(device.dev_id,)))
			History.objects.create(user_performed_task=request.user, dev_id=device, date_time=timezone.now(), action_type='Modified device', action='Modified device {0}'.format(device))
			messages.success(request, 'Database updated')
			return HttpResponseRedirect(reverse('nms:device_modify', args=(device.dev_id,)))
		else:
			return render(request, 'nms/devices_modify.html', {'device': device, 'dev_type_view': dev_type_view, 'vendor_view': vendor_view, 'dev_model_view': dev_model_view, 'os_view': os_view, 'gen_dev': gen_dev, 'request':request})
	else:
		messages.error(request, "You don't have the right permissions")
		return HttpResponseRedirect(reverse('nms:devices'))

@login_required
def user_settings(request):
	"""User settings page
	
	Location: /settings
	"""
	if request.method == 'POST':
		try:
			if request.POST['mode'] == 'chpasswd':
				password_old = request.POST['oldpassword']
				new_password = request.POST['newpassword1']
				check_new_password = request.POST['newpassword2']
				if new_password != '' or check_new_password != '':
					if request.user.check_password(password_old):
						if new_password == check_new_password:
							request.user.set_password(new_password)
							request.user.save()
							History.objects.create(action_type='User: Modify passwords', action='Password has been changed', user_performed_task=request.user, user_id=request.user, date_time=timezone.now())
							messages.success(request, 'Your password has been updated')
							#debug = list(request.POST.items())
							#messages.error(request, debug)
							return HttpResponseRedirect(reverse('nms:logout_handler'))
						else:
							messages.error(request, "The passwords you provided don't match")
							return HttpResponseRedirect(reverse('nms:user_settings'))
					else:
						messages.error(request, "Your old password is incorrect")
						return HttpResponseRedirect(reverse('nms:user_settings'))
				else:
					messages.error(request, 'The password field is empty')
					return HttpResponseRedirect(reverse('nms:user_settings'))
			elif request.POST['mode'] == 'chsettings':
				newname = request.POST['newname']
				newsurname = request.POST['newsurname']
				newemail = request.POST['newemail']
				if newname != '' and newsurname != '' and newemail != '':
					request.user.first_name = newname
					request.user.last_name = newsurname
					request.user.email = newemail
					request.user.save()
					messages.success(request, 'Attributes updated')
					History.objects.create(action_type='User: Modify settings', action='Settings modified', user_performed_task=request.user, user_id=request.user, date_time=timezone.now())
				else:
					messages.error(request, 'Not all fields were filled')
				return HttpResponseRedirect(reverse('nms:user_settings'))
		except (ValueError, KeyError):
			messages.error(request, 'Not all fields are set or an other error occured')
			return HttpResponseRedirect(reverse('nms:user_settings'))
	return render(request, 'nms/chpasswd.html', {'request':request}, context_instance=RequestContext(request))

@login_required
def send_command(request, device_id_request):
	"""View for sending commands to a device. This view redirects when done.
	
	Location: /devices/\d+/send_command
	"""
	device = Devices.objects.get(pk=device_id_request)
	groups = request.user.groups.all()
	group_device = [group for group in groups if group.dev_group_set.filter(devid=device).exists()]
	group_rights = [groups for groups in group_device if groups.permissions.filter(codename='manage_devices').exists()]
	if len(group_rights) > 0:
		uargs = {}
		if request.method == 'GET' and 'command' in request.GET:
			command = request.GET['command']
			for key in request.GET.keys():
				if key.startswith('arg:') and len(key) > 4:
					uargs[key[4:]] = request.GET[key]
		else:
			return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))
	
		
		ret = commands.executeTask(command, device, uargs, request.user)
		if ret == -1:
			messages.error(request, 'Failed to connect to device')
		else:
			msg_text = ''
			for line in ret:
				msg_text += line + '<br />'
			messages.info(request, msg_text)
		return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))
	else:
		messages.error(request, "You don't have the right permissions")
		return HttpResponseRedirect(reverse('nms:devices'))

def session_handler(request):
	"""Session handler to check if the current user is a valid user
	
	Location: /session
	"""
	if request.method == 'POST':
		try:
			username = request.POST['username']
			password = request.POST['password']
			url = request.POST['url']
			user = authenticate(username=username, password=password)
			if user is not None:
				if user.is_active:
					login(request, user)
					History.objects.create(user_performed_task=request.user, action_type='User: logged in', action='User succesfully logged in', date_time=timezone.now(), user_id=request.user)
					messages.success(request, "Successfully logged in")
					if url == "":
						return HttpResponseRedirect(reverse('nms:index'))
					else:
						return HttpResponseRedirect(request.POST['url'])
				else:
					messages.error(request, 'Your account has been disabled')
					return HttpResponseRedirect(reverse('nms:login_handler'))
			else:
				messages.error(request, 'Invalid login')
				return HttpResponseRedirect(reverse('nms:login_handler'))
		except (KeyError) as err:
			messages.error(request, "You are not logged in")
			messages.error(err)
			return HttpResponseRedirect(reverse('nms:login_handler'))
	else:
		messages.error(request, "You are not logged in 2")
		return HttpResponseRedirect(reverse('nms:login_handler'))

@login_required
def query(request):
	"""AJAX-view to query device models or SSH connection traffic.
	
	Location: /query
	"""
	if request.method == 'GET':
		if 'type' in request.GET and 'q' in request.GET and 'HTTP_REFERER' in request.META:
			qtype = request.GET['type']
			query = request.GET['q']
			referer = request.META['HTTP_REFERER']
		else:
			return HttpResponse('<Error>', content_type='text/plain')
	else:
		return HttpResponse('<Error>', content_type='text/plain')

	hostname = get_object_or_404(Settings, known_id=2)
	if not (referer.startswith('http://' + hostname.string) or referer.startswith('https://' + hostname.string)):
		return HttpResponse('<Error>', content_type='text/plain')

	if qtype == 'models' and request.user.has_perm('nms.add_devices'):
		ret_list = []
		ret_string = ''
		dtype, dvendor = query.split('|')
		gen_devs = Gen_dev.objects.all()
		for gen_dev in gen_devs:
			if gen_dev.dev_type_id.dev_type_name == dtype and gen_dev.vendor_id.vendor_name == dvendor:
				ret_list.append(str(gen_dev.model_id))
		if len(ret_list) == 0:
			return HttpResponse('<Error>', content_type='text/plain')
		for i, item in enumerate(ret_list):
			ret_string += item
			if i+1 < len(ret_list):
				ret_string += '|'
		return HttpResponse(ret_string, content_type='text/plain')
	elif qtype == 'ssh':
		if not 'dev' in request.GET:
			return HttpResponse('<Missing dev in GET>', content_type='text/plain')
		dev = request.GET['dev']
		try:
			device = Devices.objects.get(pk=dev)
			groups = request.user.groups.all()
			group_device = [group for group in groups if group.dev_group_set.filter(devid=device).exists()]
			group_rights = [groups for groups in group_device if groups.permissions.filter(codename='manage_devices').exists()]
			if len(group_rights) == 0:
				return HttpResponse('<Error>', content_type='text/plain')
		except:
			return HttpResponse('<Error>', content_type='text/plain')
		if query == 'receive':
			connection = commands.getConnection(request.user, device)
			try:
				ret = connection.receive()
			except:
				return HttpResponse('', content_type='text/plain')
			return HttpResponse(ret.decode(), content_type='text/plain')
		elif query == 'send':
			if not 'text' in request.GET:
				return HttpResponse('', content_type='text/plain')
			text = request.GET['text']
			connection = commands.getConnection(request.user, device)
			text = text + '\n'
			if type(text) != type(bytes()):
				History.objects.create(user_performed_task = request.user, action_type='Manage device', dev_id = device, action = '[dev%i] %s' % (device.dev_id, text), date_time = timezone.now())
			connection.send(text.encode())
			return HttpResponse('', content_type='text/plain')
		elif query == 'del':
			commands.removeConnection(request.user, device)
			return HttpResponse('Connection closed', content_type='text/plain')
		elif query == 'priv':
			connection = commands.getConnection(request.user, device)
			text = passwordstore.getEnablePassword(device).decode() + '\n'
			if type(text) != type(bytes()):
				History.objects.create(user_performed_task = request.user, action_type='Elevate user (manage device)', dev_id = device, action = '[dev%i] Elevating user rights' % (device.dev_id), date_time = timezone.now())
			connection.send(text.encode())
			return HttpResponse('', content_type='text/plain')
	return HttpResponse('<Unkown query type>!', content_type='text/plain')

@login_required
def logout_handler(request):
	"""Handler to terminate the current users session. Redirects when done.
	
	Location: /logout
	"""
	History.objects.create(user_performed_task=request.user, user_id=request.user, action_type='User: logged out', action='The user has been logged out', date_time=timezone.now())
	logout(request)
	messages.success(request, "You are logged out")
	return HttpResponseRedirect(reverse('nms:login_handler'))

@login_required
def device_ssh(request, device_id_request):
	"""Device-specific SSH / Telnet terminal
	
	Location: /devices/\d+/manage/ssh
	"""
	device = get_object_or_404(Devices, pk=device_id_request)
	return render(request, 'nms/ssh.html', {'device': device, 'request':request})

def license(request):
	"""Displays the licenses applicable to the application
	
	Location: /license
	"""
	return render(request, 'nms/license.html', {'request':request})

@login_required
def init(request):
	"""Application-management page for entering the master password
	
	Location: /init
	"""
	if request.method == 'POST' and 'master' in request.POST:
		master = request.POST['master']
		if passwordstore.storeMasterPassword(master) != -1:
			messages.success(request, 'Successfully updated master password')
			if 'next' in request.POST:
				return HttpResponseRedirect(request.POST['next'])
		else:
			messages.error(request, 'Invalid key length')
			if 'next' in request.POST:
				return render(request, 'nms/init.html', {'request':request, 'next':request.POST['next']})
	if request.method == 'GET' and 'next' in request.GET:
		return render(request, 'nms/init.html', {'request':request, 'next':request.GET['next']})
	return render(request, 'nms/init.html', {'request':request})

@login_required
def manage_gendev(request):
	"""This view allows the manipulation of several database tables used for generic devices.
	
	Location: /devices/gen_dev/manage
	"""
	if request.user.has_perm('nms.add_gen_dev') or request.user.has_perm('nms.delete_gen_dev') or request.user.has_perm('nms.change_gen_dev'):
		if request.method == 'POST' and 'qtype' in request.POST:
			p = request.POST
			if p['qtype'] == 'add_gendev':
				if 'dev_type' in p and 'vendor' in p and 'model' in p and 'xml_files' in p:
					try:
						Gen_dev(dev_type_id_id=int(p['dev_type']), vendor_id_id=int(p['vendor']), model_id_id=int(p['model']), file_location_id_id=int(p['xml_files'])).save()
						History.objects.create(action_type='Gendev: add', action='Added gendev', user_performed_task=request.user, date_time=timezone.now())
						messages.success(request, 'Database updated')
					except:
						messages.error(request, 'Error adding device template')
			elif p['qtype'] == 'del_gendev':
				if 'items' in p:
					for i in p.getlist('items'):
						try:
							Gen_dev.objects.get(pk=int(i)).delete()
							History.objects.create(action_type='Gendev: deleted', action='Deleted gendev', user_performed_task=request.user, date_time=timezone.now())
							messages.success(request, 'Database updated')
						except django_exception.ProtectedError:
							messages.error(request, 'Cannot delete some instances of gen_dev because there is still a reference')
						except:
							messages.error(request, 'Error deleting device template')
			elif p['qtype'] == 'add_devtype':
				if 'name' in p:
					try:
						Dev_type(dev_type_name=p['name']).save()
						History.objects.create(action_type='Gendev: add', action='Added gendev device type', user_performed_task=request.user, date_time=timezone.now())
						messages.success(request, 'Database updated')
					except:
						messages.error(request, 'Error adding device type')
			elif p['qtype'] == 'del_devtype':
				if 'items' in p:
					for i in p.getlist('items'):
						try:
							Dev_type.objects.get(pk=int(i)).delete()
							
							History.objects.create(action_type='Gendev: deleted', action='Deleted gendev device type', user_performed_task=request.user, date_time=timezone.now())
							messages.success(request, 'Database updated')
						except django_exception.ProtectedError:
							messages.error(request, 'Cannot delete some instances of dev_type because there is still a reference')
						except:
							messages.error(request, 'Error deleting device type')
			elif p['qtype'] == 'add_vendor':
				if 'name' in p:
					try:
						Vendor(vendor_name=p['name']).save()
						History.objects.create(action_type='Gendev: add', action='Added gendev vendor', user_performed_task=request.user, date_time=timezone.now())
						messages.success(request, 'Database updated')
					except:
						messages.error(request, 'Error adding vendor')
			elif p['qtype'] == 'del_vendor':
				if 'items' in p:
					for i in p.getlist('items'):
						try:
							Vendor.objects.get(pk=int(i)).delete()
							History.objects.create(action_type='Gendev: deleted', action='Deleted gendev vendor', user_performed_task=request.user, date_time=timezone.now())
							messages.success(request, 'Database updated')
						except django_exception.ProtectedError:
							messages.error(request, 'Cannot delete some instances of vendor because there is still a reference')
						except:
							messages.error(request, 'Error deleting vendor')
			elif p['qtype'] == 'add_model':
				if 'name' in p:
					try:
						Dev_model(model_name=p['name']).save()
						History.objects.create(action_type='Gendev: add', action='Added gendev model', user_performed_task=request.user, date_time=timezone.now())
						messages.success(request, 'Database updated')
					except:
						messages.error(request, 'Error adding model')
			elif p['qtype'] == 'del_model':
				if 'items' in p:
					for i in p.getlist('items'):
						try:
							Dev_model.objects.get(pk=int(i)).delete()
							History.objects.create(action_type='Gendev: deleted', action='Deleted gendev model', user_performed_task=request.user, date_time=timezone.now())
							messages.success(request, 'Database updated')
						except django_exception.ProtectedError:
							messages.error(request, 'Cannot delete some instances of model because there is still a reference')
						except:
							messages.error(request, 'Error deleting model')
			elif p['qtype'] == 'add_xml':
				if 'name' in p:
					try:
						file_data = request.FILES['file']
						if file_data.content_type != 'text/xml':
							messages.error(request,"The uploaded file isn't a XML-file")
							return HttpResponseRedirect(reverse('nms:manage_gendev'))
						try:
							ElementTree.parse(file_data)
							messages.success(request, 'Well formatted XML-file received')
						except:
							messages.error(request, 'Not well formatted XML-file')
							return HttpResponseRedirect(reverse('nms:manage_gendev'))
						destination = os_library.path.abspath(os_library.path.dirname(nms.__file__)) + '/static/devices/' + p['name']
						file = open(destination, 'wb+')
						for item in file_data:
							file.write(item)
						file.close()
						File_location(location=destination).save()	
						History.objects.create(action_type='Gendev: add', action='Added gendev XML', user_performed_task=request.user, date_time=timezone.now())
						messages.success(request, 'Database updated')
					except:
						messages.error(request, list(request.POST.items()))
						messages.error(request, traceback.format_exc()) #debug code
						messages.error(request, 'Error adding XML')
			elif p['qtype'] == 'del_xml':
				if 'items' in p:
					for i in p.getlist('items'):
						try:
							file = File_location.objects.get(pk=int(i))
							file.delete()
							if not os_library.path.isfile(file.location):
								messages.info(request, "File doesn't exist")
							else:
								os_library.remove(file.location)
								messages.info(request, "File found and trying to removing it")
							History.objects.create(action_type='Gendev: deleted', action='Deleted gendev XML', user_performed_task=request.user, date_time=timezone.now())
							messages.success(request, 'Database updated')
						except django_exception.ProtectedError:
							messages.error(request, 'Cannot delete some instances of xml because there is still a reference')
						except:
							messages.error(request, 'Error deleting XML')
			elif p['qtype'] == 'add_os_type':
				if 'name' in p:
					try:
						OS_type(type=p['name']).save()
						History.objects.create(action_type='Gendev: add', action='Added gendev OS type', user_performed_task=request.user, date_time=timezone.now())
						messages.success(request, 'Database updated')
					except:
						messages.error(request, 'Error adding model')
			elif p['qtype'] == 'del_os_type':
				if 'items' in p:
					for i in p.getlist('items'):
						try:
							OS_type.objects.get(pk=int(i)).delete()
							History.objects.create(action_type='Gendev: deleted', action='Deleted gendev OS type', user_performed_task=request.user, date_time=timezone.now())
							messages.success(request, 'Database updated')
						except django_exception.ProtectedError:
							messages.error(request, 'Cannot delete some instances of OS_type because there is still a reference')
						except:
							messages.error(request, 'Error deleting model')
			elif p['qtype'] == 'add_os':
				if 'vendor_id' in p and 'os_type_id' in p:
					try:
						os = OS()
						os.vendor_id = Vendor.objects.get(pk=request.POST['vendor_id'])
						os.os_type_id =	OS_type.objects.get(pk=request.POST['os_type_id'])
						os.build = request.POST['build']
						os.short_info = request.POST['short_info']
						os.name = request.POST['name']		
						os.save()
						History.objects.create(action_type='Gendev: add', action='Added gendev OS', user_performed_task=request.user, date_time=timezone.now())
						messages.success(request, 'Database updated')
					except:
						messages.error(request, 'Error adding model')
			elif p['qtype'] == 'del_os':
				if 'items' in p:
					for i in p.getlist('items'):
						try:
							OS.objects.get(pk=int(i)).delete()
							History.objects.create(action_type='Gendev: deleted', action='Deleted gendev OS', user_performed_task=request.user, date_time=timezone.now())
							messages.success(request, 'Database updated')
						except django_exception.ProtectedError:
							messages.error(request, 'Cannot delete some instances of OS because there is still a reference')
						except:
							messages.error(request, 'Error deleting model')
			
			elif p['qtype'] == 'add_osdev':
				if 'os' in p and 'gen_dev' in p:
					try:
						OS_dev.objects.create(os_id=OS.objects.get(pk=p['os']), gen_dev_id=Gen_dev.objects.get(pk=p['gen_dev']))
						History.objects.create(action_type='Gendev: add', action='Added gendev OS device', user_performed_task=request.user, date_time=timezone.now())
						messages.success(request, 'Database updated')
					except:
						messages.error(request, 'Error adding model')
			elif p['qtype'] == 'del_osdev':
				if 'items' in p:
					for i in p.getlist('items'):
						try:
							OS_dev.objects.get(pk=int(i)).delete()
							History.objects.create(action_type='Gendev: deleted', action='Deleted gendev OS device', user_performed_task=request.user, date_time=timezone.now())
							messages.success(request, 'Database updated')
						except django_exception.ProtectedError:
							messages.error(request, 'Cannot delete some instances of OS_dev because there is still a reference')
						except:
							messages.error(request, 'Error deleting model')
			
					
						
			
			
		dev_types = Dev_type.objects.all()
		vendors = Vendor.objects.all()
		models = Dev_model.objects.all()
		xml_files = File_location.objects.all()
		gen_devs = Gen_dev.objects.all()
		os = OS.objects.all()
		os_devs = OS_dev.objects.all()
		os_type = OS_type.objects.all()
		if request.method == 'POST':
			return HttpResponseRedirect(reverse('nms:manage_gendev'))
		else:
			return render(request, 'nms/manage_gendev.html', {'request':request, 'dev_types':dev_types, 'vendors':vendors, 'models':models, 'xml_files':xml_files, 'gen_devs':gen_devs, 'os':os, 'os_devs':os_devs, 'os_type': os_type})
	else:
		messages.error(request, "You don't have the right permissions to access this page.")
		return HttpResponseRedirect(reverse('nms:devices'))
	
@login_required
def history(request, device_id_request):
	"""Shows the logged history of a device
	
	Location: /devices/\d+/history
	"""
	if request.user.has_perm('nms.manage_devices'):
		device = get_object_or_404(Devices, pk=device_id_request)
		history_items_list = History.objects.filter(dev_id=device)
		history_items_list = history_items_list.extra(order_by = ['-history_id'])
		paginator = Paginator(history_items_list, 25)
	
		page = request.GET.get('page')
		try:
			history_items = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			history_items = paginator.page(1)
		except EmptyPage:
			history_items = paginator.page(paginator.num_pages)
			
		
		
		return render(request, 'nms/devices_history.html', {'request': request, 'history': history_items})
	else:
		messages.error(request, "You don't have the right permissions")
		return HttpResponseRedirect(reverse('nms:devices'))
		
@login_required
def user_history(request):
	"""Shows the user-specific history
	
	Location: /history
	"""
	history_items_list = History.objects.filter(Q(user_id = request.user) | Q(user_performed_task = request.user ))
	history_items_list = history_items_list.extra(order_by = ['-history_id'])
	paginator = Paginator(history_items_list, 25)
	
	page = request.GET.get('page')
	try:
		history_items = paginator.page(page)
	except PageNotAnInteger:
		# If page is not an integer, deliver first page.
		history_items = paginator.page(1)
	except EmptyPage:
		history_items = paginator.page(paginator.num_pages)
	return render(request, 'nms/user_history.html', {'request': request, 'history': history_items})

@login_required
def acl_user_history(request, acl_user):
	"""Application administrator page for listing user-specific history
	
	Location: /acl/users/\d+/history
	"""
	if request.user.has_perm('auth.list_user'):
		group_count = Group.objects.count()
		user_count = User.objects.count()
		devices_count = Devices.objects.count()
		user_obj = get_object_or_404(User, pk=acl_user)
		history_items_list = History.objects.filter(Q(user_id = user_obj ) | Q(user_performed_task = user_obj ))
		history_items_list = history_items_list.extra(order_by = ['-history_id'])
		paginator = Paginator(history_items_list, 25)
	
		page = request.GET.get('page')
		try:
			history_items = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			history_items = paginator.page(1)
		except EmptyPage:
			history_items = paginator.page(paginator.num_pages)
		return render(request, 'nms/acl_user_history.html', {'request': request, 'history': history_items, 'group_count': group_count, 'user_count': user_count, 'devices_count': devices_count})
	else:
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_device_history(request, acl_id):
	"""Application administrator page for listing device-specific history
	
	Location: /acl/devices/\d+/history
	"""
	if request.user.has_perm('auth.list_group'):
		device = get_object_or_404(Devices, pk=acl_id)
		history_items_list = History.objects.filter(dev_id=device)
		history_items_list = history_items_list.extra(order_by = ['-history_id'])
		paginator = Paginator(history_items_list, 25)
	
		page = request.GET.get('page')
		try:
			history_items = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			history_items = paginator.page(1)
		except EmptyPage:
			history_items = paginator.page(paginator.num_pages)
			
		
		
		return render(request, 'nms/acl_devices_history.html', {'request': request, 'history': history_items})
	else:
		return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_kick_user(request, user_id):
	"""User-kick handler. Redirects when done.
	
	Location: /acl/users/\d+/kick
	"""
	user_obj = get_object_or_404(User, pk=user_id)
	if request.user.has_perm('auth.change_user') and user_obj.username != 'root':
		[x.delete() for x in Session.objects.all() if x.get_decoded().get('_auth_user_id') == user_obj.id]
		History.objects.create(action_type='ACL: Kick user', action='Kicked user {0}'.format(user_obj), user_id = user_obj, user_performed_task = request.user, date_time = timezone.now())
		messages.success(request, 'User {0} is kicked out of the current sessions.'.format(user_obj))
		return HttpResponseRedirect(reverse('nms:acl_user'))
	else:
		return HttpResponseRedirect(reverse('nms:index'))

@login_required
def change_gendev_handler(request, gendev_id):
	"""Handler for changing gen_dev related tables. Redirects when done
	
	Location: /devices/gen_dev/change/\d+/handler
	"""
	if request.user.has_perm('nms.change_gen_dev') and 'qtype' in request.POST:
		p = request.POST
		if p['qtype'] == 'change_os':
			try:
				os = OS.objects.get(pk=gendev_id)
				os.vendor_id = Vendor.objects.get(pk=p['vendor_id'])
				os.type_id = OS_type.objects.get(pk=p['os_type_id'])
				os.build = p['build']
				os.short_info = p['short_info']
				os.name = p['name']
				os.save()
				messages.success(request, 'Database successfully updated')
			except:
				messages.error(request, 'Error occured during the request. Can not change OS')
		elif p['qtype'] == 'change_os_type':
			try:
				os_type = OS_type.objects.get(pk=gendev_id)
				os_type.type = p['type']
				os_type.save()
				messages.success(request, 'Database successfully updated')
			except:
				messages.error(request, 'Error occured during the request. Can not change OS type')
		elif p['qtype'] == 'change_os_dev':
			try:
				os_dev = OS_dev.objects.get(pk=gendev_id)
				os_dev.os_id = OS_dev.objects.get(pk=p['os_id'])
				os_dev.gen_dev_id = Gen_dev.objects.get(pk=p['gen_dev_id'])
				os_dev.save()
				messages.success(request, 'Database successfully updated')
			except:
				messages.error(request, traceback.format_exc())
				messages.error(request, 'Error occured during the request. Can not change OS device relationship')
		elif p['qtype'] == 'change_gendev':
			try:
				gen_dev = Gen_dev.objects.get(pk=gendev_id)
				gen_dev.vendor_id = Vendor.objects.get(pk=p['vendor_id'])
				gen_dev.model_id = Dev_model.objects.get(pk=p['model_id'])
				gen_dev.dev_type_id = Dev_type.objects.get(pk=p['dev_type_id'])
				gen_dev.file_location_id = File_location.objects.get(pk=p['file_location_id'])
				gen_dev.save()
				messages.success(request, 'Database successfully updated')
			except:
				messages.error(request, traceback.format_exc())
				messages.error(request, 'Error occured during the request. Can not change generic device')
		elif p['qtype'] == 'change_dev_type':
			try:
				dev_type = Dev_type.objects.get(pk=gendev_id)
				dev_type.dev_type_name = p['dev_type_name']
				dev_type.save()
				messages.success(request, 'Database successfully updated')
			except:
				messages.error(request, 'Error occured during the request. Can not change device type')
		elif p['qtype'] == 'change_vendor':
			
			try:
				vendor = Vendor.objects.get(pk=gendev_id)
				vendor.vendor_name = p['vendor_name']
				vendor.save()
				messages.success(request, 'Database successfully updated')
			except:
				messages.error(request, 'Error occured during the request. Can not change vendor')
		elif p['qtype'] == 'change_model':
			try:
				dev_model = Dev_model.objects.get(pk=gendev_id)
				dev_model.model_name = p['model_name']
				dev_model.version = p['version']
				dev_model.save()
				messages.success(request, 'Database successfully updated')
			except:
				messages.error(request, traceback.format_exc())
				messages.error(request, 'Error occured during the request. Can not change model')
		elif p['qtype'] == 'change_xml':
			if 'file' in request.FILES:
				try:
					file_data = request.FILES['file']
					if file_data.content_type != 'text/xml':
						messages.error(request,"The uploaded file isn't a XML-file")
						return HttpResponseRedirect(reverse('nms:manage_gendev'))
					try:
						ElementTree.parse(file_data)
						messages.success(request, 'Well formatted XML-file received')
					except:
						messages.error(request, 'Not well formatted XML-file')
						return HttpResponseRedirect(reverse('nms:change_gendev', args=(gendev_id,)))
					file_location = File_location.objects.get(pk=gendev_id)
					if not os_library.path.isfile(file_location.location):
						messages.info(request, "File doesn't exist")
					else:
						os_library.remove(file_location.location)
						messages.info(request, "File found and trying to removing it")
					destination = os_library.path.abspath(os_library.path.dirname(nms.__file__)) + '/static/devices/' + p['name']
					file = open(destination, 'wb+')
					for item in file_data:
						file.write(item)
					file.close()
					file_location.location = destination
					file_location.save()
					messages.success(request, 'Database successfully updated')
				except:
					messages.error(request, traceback.format_exc())
					messages.error(request, 'Error occured during the request. Can not change XML')
			else:
				messages.error(request, 'No file received during POST')
		else:
			messages.error(request, 'No valid qtype defined in POST')
		
		return HttpResponseRedirect(reverse('nms:manage_gendev'))
	else:
		messages.error(request, "You don't have the right permissions to access this page")
		return HttpResponseRedirect(reverse('nms:index'))

@login_required
def change_gendev(request, gendev_id):
	"""Page for allowing users to change gendev records
	
	Location: /devices/gen_dev/\d+/change
	"""
	if request.user.has_perm('nms.change_gen_dev') and 'qtype' in request.GET:
		qtype = request.GET['qtype']
		if qtype == 'change_os':
			vendors = Vendor.objects.all()
			os_type = OS_type.objects.all()
			object = OS.objects.get(pk=gendev_id)
			return render(request, 'nms/change_gendev.html', {'request': request, 'qtype': qtype, 'object': object, 'vendors': vendors, 'os_type': os_type})
		elif qtype == 'change_os_type':
			object = OS_type.objects.get(pk=gendev_id)
		elif qtype == 'change_os_dev':
			os = OS.objects.all()
			gen_devs = Gen_dev.objects.all()
			object = OS_dev.objects.get(pk=gendev_id)
			return render(request, 'nms/change_gendev.html', {'request': request, 'qtype': qtype, 'object': object, 'os': os, 'gen_devs': gen_devs})
		elif qtype == 'change_gendev':
			vendors = Vendor.objects.all()
			dev_type = Dev_type.objects.all()
			models = Dev_model.objects.all()
			xml = File_location.objects.all()
			object = Gen_dev.objects.get(pk=gendev_id)
			return render(request, 'nms/change_gendev.html', {'request': request, 'qtype': qtype, 'object': object, 'vendors': vendors, 'dev_type': dev_type, 'models': models, 'xml': xml})
		elif qtype == 'change_dev_type':
			object = Dev_type.objects.get(pk=gendev_id)
		elif qtype == 'change_vendor':
			object = Vendor.objects.get(pk=gendev_id)
		elif qtype == 'change_model':
			object = Dev_model.objects.get(pk=gendev_id)
		elif qtype == 'change_xml':
			object = File_location.objects.get(pk=gendev_id)
			file_name = object.location.split('/')[-1]
			return render(request, 'nms/change_gendev.html', {'request': request, 'qtype': qtype, 'object': object, 'file_name': file_name})
		elif qtype == 'change_dev_type':
			object = Dev_type.objects.get(pk=gendev_id)
		else:
			messages.error(request, 'No valid qtype found')
			return HttpResponseRedirect(reverse('nms:devices'))
		return render(request, 'nms/change_gendev.html', {'request': request, 'qtype': qtype, 'object': object})
	else:
		messages.error(request, "You don't have the right permissions or qtype is not found in request.")
		return HttpResponseRedirect(reverse('nms:manage_gendev'))