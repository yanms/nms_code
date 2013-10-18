from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
from django.core.urlresolvers import reverse
from nms.models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import nms.commands as commands


@login_required
def index(request):
	return HttpResponseRedirect(reverse('nms:devices'))

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
				messages.info(request, 'Your accounts is created. An administrator has to activate your account')
				return HttpResponseRedirect(reverse('nms:register'))
			else:
				messages.error(request, 'Password mismatch')
				return HttpResponseRedirect(request('nms:register'))
		else:
			messages.info(request, 'User already exists')
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
	return render(request, 'nms/devices.html')

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
		
		messages.info(request, 'Database updated')
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
	devices = get_object_or_404(Devices, pk=device_id_request)
	return render(request, 'nms/modify_device.html', {'devices': devices})

@login_required
def user_settings(request):
	return render(request, 'nms/chpasswd.html')


def send_command(request, device_id, cmd_name, args):
	device = Devices.objects.get(pk=device_id)
	commands = commands.Connection()
	commands.demo_connectDevice(device.ip, device.username, device.password, device.port)
	if cmd_name == 'shutdown':
		ret = commands.demo_shutdown(args[0])
	elif cmd_name == 'noshutdown':
		ret = commands.demo_noshutdown(args[0])
	elif cmd_name == 'interfaceip':
		ret = commands.demo_interfaceip(args[0], args[1])
	elif cmd_name == 'interfacedescription':
		ret = commands.demo_interfacedescription(args[0], args[1])
	elif cmd_name == 'shotipinterfacebrief':
		ret = commands.demo_showipinterfacebrief()
	commands.demo_closeDevice()
	return HttpResponseRedirect(reverse('nms:device_manager', device_id))

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
					messages.info(request, "Successfully loged in")
					if url == "":
						return HttpResponseRedirect(reverse('nms:devices'))
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
	messages.info(request, "You are logged out")
	return HttpResponseRedirect(reverse('nms:login_handler'))
