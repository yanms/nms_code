from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
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
			
		except (KeyError, ValueError) as err:
			messages.error(request, 'Not all fields are set or an other error occured')
			print(err)
			print(ip_recv)
			#return HttpResponse(request.POST.items())
			return HttpResponseRedirect(reverse('nms:nms_admin_add_device'))
		
		messages.info(request, 'Database updated')
		return HttpResponseRedirect(reverse('nms:nms_admin_add_device'))
	else:
		return render(request, 'nms/add_device.html', {'dev_type_view': dev_type_view, 'vendor_view': vendor_view, 'dev_model_view' : dev_model_view, 'os_view': os_view, 'gen_dev': gen_dev})
