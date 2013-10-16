from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from nms.models import *
from django.contrib import messages


def index(request):
	return HttpResponse('index page')

def register(request):
	return HttpResponse('register page.')

def nms_admin(request):
	return render(request, 'nms/devices.html')

def nms_admin_login(request):
	return render(request, 'nms/login.html')

def nms_admin_add_device(request):
	dev_type_view = Dev_type.objects.all()
	vendor_view = Vendor.objects.all()
	dev_model_view = Dev_model.objects.all()
	os_view = OS.objects.all()
	if request.method == 'POST':
		#return HttpResponse('Received post method.')
		q = Devices()
		
		
		try:
			dev_type = request.POST['dev_type']
			vendor = Vendor.objects.filter(vendor_name = request.POST['vendor_name'])
			dev = Dev_model.objects.filter(model_name = request.POST['dev_model'])
			os_name = request.POST['os_name']
			pref_remote_prot = request.POST['pref_remote_prot']
			ipprot = request.POST['ipprot']
			ip = request.POST['ip']
			port = request.POST['port']
			login_name = request.POST['login_name']
			password_remote = request.POST['password_remote']
			password_enable = request.POST['password_enable']
		except KeyError:
			messages.error(request, 'Not all fields are set')
			return HttpResponseRedirect(reverse('nms:nms_admin_add_device'))
		
		
		messages.info(request, 'Database updated')
		return HttpResponseRedirect(reverse('nms:nms_admin_add_device'))
	else:
		return render(request, 'nms/add_device.html', {'dev_type_view': dev_type_view, 'vendor_view': vendor_view, 'dev_model_view' : dev_model_view, 'os_view': os_view})
