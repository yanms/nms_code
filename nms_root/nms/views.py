from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from nms.models import *


def index(request):
	return HttpResponse('index page')

def register(request):
	return HttpResponse('register page.')

def nms_admin(request):
	return render(request, 'nms/devices.html')

def nms_admin_login(request):
	return render(request, 'nms/login.html')

def nms_admin_add_device(request):
	if request.method == 'POST':
		#return HttpResponse('Received post method.')
		q = Devices()
		try:
			dev_type = request.POST['dev_type']
			vendor_name = request.POST['vendor_name']
			dev_model = request.POST['dev_model']
			os_name = request.POST['os_name']
			pref_remote_prot = request.POST['pref_remote_prot']
			ipprot = request.POST['ipprot']
			ip = request.POST['ip']
			port = request.POST['port']
			login_name = request.POST['login_name']
			password_remote = request.POST['password_remote']
			password_enable = request.POST['password_enable']
		except KeyError:
				return render(request, 'nms/add_device.html', {'error_message': 'Not all fields are set'})
		
		
		return HttpResponseRedirect(reverse('nms:nms_admin_add_device'))
	else:
		return render(request, 'nms/add_device.html')
