from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse

def index(request):
	return HttpResponse('Index page should be displayed here.')

def register(request):
	return HttpResponse('register page.')

def nms_admin(request):
	return HttpResponse('nms_admin page.')

def nms_admin_login(request):
	return HttpResponse('nms_admin_login')

def nms_admin_add_device(request):
	return HttpResponse('nms_admin_add_device.')
