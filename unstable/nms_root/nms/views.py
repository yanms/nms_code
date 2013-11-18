from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
from django.core.urlresolvers import reverse
from nms.models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Permission
from django.contrib.auth.decorators import login_required
import nms.commands as commands


@login_required
def index(request):
	return render(request, 'nms/index.html', {'user': request.user.get_username()})

@login_required
def acl(request):
    user_obj = request.user
    return render(request, 'nms/acl.html', {'user_permissions': user_obj.user_permissions.all(), 'existing_permissions': Permission.objects.values()})

@login_required
def acl_list(request):
    return render(request, 'nms/acl_list.html', {'users': User.objects.values()})
    
@login_required
def acl_user_manage(request, acl_user):
    user_obj = get_object_or_404(User, pk=acl_user)
    return render(request, 'nms/acl_user_manage.html', {'user_obj': user_obj, 'existing_permissions': Permission.objects.values()})

def register(request):
	if request.method == 'POST':
		username = request.POST['username']
		password = request.POST['password']
		password_check = request.POST['password1']
		check_username = User.objects.filter(username=username).exists()
		if not check_username:
			if password == password_check:
				user = User.objects.create_user(username=username, password=password)
				user.is_active = False
				user.save()
				messages.success(request, 'Your accounts is created. An administrator has to activate your account')
				return HttpResponseRedirect(reverse('nms:register'))
			else:
				messages.error(request, 'Password mismatch')
				return HttpResponseRedirect(request('nms:register'))
		else:
			messages.error(request, 'User already exists')
			return HttpResponseRedirect(reverse('nms:register'))
	else:
		return render(request, 'nms/register.html')
			

def login_handler(request):
	if (request.method == 'GET' and 'next' in request.GET):
		url = request.GET['next']
		return(render(request, 'nms/login.html', {'url': url}))
	else:
		return render(request, 'nms/login.html')

@login_required
def devices(request):
	devices = Devices.objects.all()
	return render(request, 'nms/devices.html', {'devices': devices})

@login_required
def device_add(request):
	dev_type_view = Dev_type.objects.all()
	vendor_view = Vendor.objects.all()
	dev_model_view = Dev_model.objects.all()
	os_view = OS_dev.objects.all()
	gen_dev = Gen_dev.objects.all()
	if request.method == 'POST':
		#return HttpResponse('Received post method.')
		q = Devices()
		
		try:
			dev = get_object_or_404(Gen_dev, pk=request.POST['gen_dev_id'])
			os = get_object_or_404(OS_dev, pk=request.POST['os_dev_id'])
			pref_remote_prot = request.POST['pref_remote_prot']
			ipprot = request.POST['ipprot']
			ip_recv = request.POST['ipaddr']
			port = request.POST['port']
			login_name = request.POST['login_name']
			password_remote = request.POST['password_remote']
			password_enable = request.POST['password_enable']
			device = Devices(gen_dev_id=dev, os_dev_id=os, ip=ip_recv, pref_remote_prot=pref_remote_prot, 
			ip_version = ipprot, login_name = login_name, password_remote=password_remote, password_enable=password_enable, port=port)
			device.save()
			
		except (KeyError, ValueError, NameError, UnboundLocalError) as err:
			messages.error(request, 'Not all fields are set or an other error occured')
			messages.error(request, err)
			print(err)
			#return HttpResponse(request.POST.items())
			return HttpResponseRedirect(reverse('nms:device_add'))
		
		messages.success(request, 'Database updated')
		return HttpResponseRedirect(reverse('nms:device_add'))
	else:
		return render(request, 'nms/add_device.html', {'dev_type_view': dev_type_view, 'vendor_view': vendor_view,
		 'dev_model_view' : dev_model_view, 'os_view': os_view, 'gen_dev': gen_dev})
		
@login_required
def device_manager(request, device_id_request):
	devices = get_object_or_404(Devices, pk=device_id_request)
	return render(request, 'nms/manage_device.html', {'devices': devices})

@login_required
def device_modify(request, device_id_request):
	device = get_object_or_404(Devices, pk=device_id_request)
	gen_dev = Gen_dev.objects.all()
	os_dev = OS_dev.objects.all()
	if request.method == 'POST':
		try:
			device = get_object_or_404(Devices, pk=device_id_request)
			dev_type = get_object_or_404(Gen_dev, pk=request.POST['gen_dev_id'])
			os = get_object_or_404(OS_dev, pk=request.POST['os_dev_id'])
			pref_remote_prot = request.POST['pref_remote_prot']
			ipprot = request.POST['ipprot']
			ip_recv = request.POST['ipaddr']
			port = request.POST['port']
			login_name = request.POST['login_name']
			password_remote = request.POST['password_remote']
			password_enable = request.POST['password_enable']
			device.gen_dev_id = dev_type
			device.os_dev_id = os
			device.pref_remote_prot = pref_remote_prot
			device.ip_version = ipprot
			device.ip = ip_recv
			device.port = port
			device.login_name = login_name
			device.password_remote = password_remote
			device.password_enable = password_enable
			device.save()
			messages.success(request, 'Database updated successfully.')
			return HttpResponseRedirect(reverse('nms:device_add', args=(device_id_request,)))
		except (KeyError, ValueError):
			messages.error(request, 'Not all fields are are set or an other error occured')
			return HttpResponseRedirect(reverse('nms:device_add', args=(device_id_request,)))
	else:
		return render(request, 'nms/modify_device.html', {'devices': device, 'gen_dev': gen_dev, 'os_dev': os_dev})

@login_required
def user_settings(request):
	if request.method == 'POST':
		try:
			password_old = request.POST['oldpassword']
			new_password = request.POST['newpassword1']
			check_new_password = request.POST['newpassword2']
			if new_password != '' or check_new_password != '':
				if request.user.check_password(password_old):
					if new_password == check_new_password:
						request.user.set_password(new_password)
						request.user.save()
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
		except (ValueError, KeyError):
			messages.error(request, 'Not all fields are set or an other error occured')
			return HttpResponseRedirect(reverse('nms:user_settings'))
	else:	
		return render(request, 'nms/chpasswd.html')

@login_required
def send_command(request, device_id_request):
	if request.method == 'GET' and 'command' in request.GET:
		command = request.GET['command']
	else:
		return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))

	device = Devices.objects.get(pk=device_id_request)
	connector = commands.Connector()
	connector.demo_connectDevice(device.ip, device.login_name, device.password_remote, device.port)

	ret = ''
	if command == 'shutdown':
		if 'interface' in request.GET:
			interface = request.GET['interface']
			ret = connector.demo_shutdown(interface)
		else:
			return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))
	elif command == 'noshutdown':
		if 'interface' in request.GET:
			interface = request.GET['interface']
			ret = connector.demo_noshutdown(interface)
		else:
			return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))
	elif command == 'interfaceip':
		if 'interface' in request.GET and 'ip' in request.GET and 'subnet' in request.GET:
			interface = request.GET['interface']
			ip = request.GET['ip']
			subnet = request.GET['subnet']
			ret = connector.demo_interfaceip(interface, ip, subnet)
		else:
			return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))
	elif command == 'interfacedescription':
		if 'interface' in request.GET and 'description' in request.GET:
			interface = request.GET['interface']
			description = request.GET['description']
			ret = connector.demo_interfacedescription(interface, description)
		else:
			return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))
	elif command == 'showipinterfacebrief':
		ret = connector.demo_showipinterfacebrief()

	messages.success(request, ret)
	connector.demo_closeDevice()
	return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))

def session_handler(request):
	if request.method == 'POST':
		try:
			username = request.POST['username']
			password = request.POST['password']
			url = request.POST['url']
			user = authenticate(username=username, password=password)
			if user is not None:
				if user.is_active:
					login(request, user)
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

def logout_handler(request):
	logout(request)
	messages.success(request, "You are logged out")
	return HttpResponseRedirect(reverse('nms:login_handler'))
