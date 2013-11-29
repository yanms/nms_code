from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
from django.core.urlresolvers import reverse
from nms.models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Permission, Group
from django.contrib.auth.decorators import login_required, permission_required
from django.template import RequestContext
from django.contrib.contenttypes.models import ContentType
import nms.commands as commands
import nms.xmlparser as xmlparser
import nms.passwordstore as passwordstore
import traceback


@login_required
def index(request):
	return render(request, 'nms/index.html', {'user': request.user.get_username(), 'request':request})

def install(request):
    if Settings.objects.filter(known_name='install complete').exists():
        if Settings.objects.filter(known_name='install complete', known_boolean=True).exists():
            return HttpResponse('Installation already finished.') 
    else:
        content_type = ContentType.objects.get_for_model(User)
        list_user, created = Permission.objects.get_or_create(codename='list_user', name='Can list users', content_type=content_type)
        content_type = ContentType.objects.get_for_model(Group)
        list_group, created = Permission.objects.get_or_create(codename='list_group', name='Can list (dev) groups', content_type=content_type)
        content_type = ContentType.objects.get_for_model(Devices)
        manage_devices, created = Permission.objects.get_or_create(codename='manage_devices', name='Can manage devices (perform action)', content_type=content_type)
        content_type = ContentType.objects.get_for_model(Devices)
        list_devices, created = Permission.objects.get_or_create(codename='list_devices', name='Can list devices', content_type=content_type)
        
        group, created = Group.objects.get_or_create(name='usr:staff')
        add_group = Permission.objects.get(codename='add_group')
        change_group = Permission.objects.get(codename='change_group')
        delete_group = Permission.objects.get(codename='delete_group')
        group.permissions = [add_group, change_group, delete_group, list_group]
        
        group, created = Group.objects.get_or_create(name='usr:admin')
        add_user = Permission.objects.get(codename='add_user')
        change_user = Permission.objects.get(codename='change_user')
        delete_user = Permission.objects.get(codename='delete_user')
        group.permissions = [add_user, change_user, delete_user, list_user, add_group, change_group, delete_group, list_group]
        
        
        
        Settings.objects.create(known_id=1, known_name='install complete', known_boolean=True)
        return HttpResponse('Finished installing NMS.')

@login_required
def acl(request):
    user_obj = request.user
    return render(request, 'nms/acl.html', {'request':request})

@login_required
def acl_groups(request):
    if request.user.has_perm('auth.list_user') or request.user.has_perm('auth.add_group') or request.user.has_perm('auth.change_group') or request.user.has_perm('auth.delete_group'):
        user = request.user
        user_perm = user.has_perm('auth.list_group')
        dev_groups = Group.objects.filter(name__startswith='dev:')
        usr_groups = Group.objects.filter(name__startswith='usr:')
        return render(request, 'nms/acl_groups.html', {'user_perm': user_perm, 'dev_groups': dev_groups, 'usr_groups': usr_groups, 'request':request})
    else:
        messages.error(request, 'You do not have the right permissions to access this page')
        return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_user(request):
    if request.user.has_perm('auth.list_user') or request.user.has_perm('auth.add_user') or request.user.has_perm('auth.delete_user') or request.user.has_perm('auth.change_user'):
        user_list = User.objects.all() 
        return render(request, 'nms/acl_users.html', {'user_list': user_list,'request':request})
    else:
        messages.error(request, 'You do not have the right permissions to access this page')
        return HttpResponseRedirect(reverse('nms:acl'))

@login_required
@permission_required('auth.add_user', login_url='/permissions/?per=add_user')
def acl_user_add(request):
    return render(request, 'nms/acl_user_add.html', {'request':request})

@login_required
@permission_required('auth.add_user', login_url='/permissions/?per=add_user')
def acl_user_add_handler(request):
    if request.method == 'POST':
        try:
            username = request.POST['username']
            firstname = request.POST['firstname']
            lastname = request.POST['surname']
            email = request.POST['emailaddress']
            password = request.POST['password']
            password_check = request.POST['password2']
            check = User.objects.filter(username=username).exists()
            if check:
                messages.error(request, 'User already exists.')
                return HttpResponseRedirect(reverse('nms:acl_user_add'))
            if password == password_check:
                user = User.objects.create()
                user.username = username
                user.first_name = firstname
                user.last_name = lastname
                user.email = email
                user.set_password(password)
                user.save()
                messages.success(request, "Database updated successfully.")
                return HttpResponseRedirect(reverse('nms:acl_user_add'))
        except KeyError as err:
            messages.error(request, "Not all fields are set")
            messages.error(request, err)
            return HttpResponseRedirect(reverse('nms:acl_user_add'))
    else:
        messages.error(request, "Invalid method")
        return HttpResponseRedirect(reverse('nms:acl_user_add'))

@login_required
def acl_user_manage(request, acl_user):
    if request.user.has_perm('auth.change_user'):
        user_obj = get_object_or_404(User, pk=acl_user)
        groups = Group.objects.all()
        is_active_check = 'checked' if user_obj.is_active else ''
        return render(request, 'nms/acl_user_manage.html', {'user_obj': user_obj, 'groups': groups, 'request':request, 'is_active_check': is_active_check})
    else:
        messages.error(request, 'You do not have the right permissions to access this page')
        return HttpResponseRedirect(reverse('nms:acl'))

@login_required
@permission_required('auth.change_user', login_url='/permissions/?per=change_user')
def acl_user_manage_handler(request, acl_user):
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
                user_obj.set_password(password)
                user_obj.save()
                messages.success(request, "Database successfully updated.")
                return HttpResponseRedirect(reverse('nms:acl_user_manage', args=(acl_user,)))
            else:
               messages.error(request, "Passwords are not the same")
               return HttpResponseRedirect(reverse('nms:acl_user_add')) 
        except KeyError:
            messages.error(request, "Not all fields are set")
            return HttpResponseRedirect(reverse('nms:acl_user_add'))
    messages.error(request, "Invalid method")
    return HttpResponseRedirect(reverse('nms:acl_user_add'))

@login_required
def acl_device(request):
    if request.user.has_perm('nms.add_devices') or request.user.has_perm('nms.delete_devices') or request.user.has_perm('auth.list_group'):
        devices = Devices.objects.all() 
        return render(request, 'nms/acl_devices.html', {'devices': devices,'request':request})
    else:
        messages.error(request, 'You do not have the right permissions to access this page')
        return HttpResponseRedirect(reverse('nms:acl'))
    

@login_required
def acl_device_manage(request, acl_id):
    if request.user.has_perm('auth.list_group'):
        dev_obj = get_object_or_404(Devices, pk=acl_id)
        dev_groups = Group.objects.filter(name__startswith='dev:')
        check = Dev_group.objects.filter(devid=dev_obj)
        checked = []
        for iter in check:
            checked.append(iter.gid)
        return render(request, 'nms/acl_devices_manage.html', {'dev_obj': dev_obj, 'dev_groups': dev_groups, 'checked': checked, 'request':request})
    else:
        messages.error(request, 'You do not have the right permissions to access this page')
        return HttpResponseRedirect(reverse('nms:acl'))

@login_required
def acl_handler(request, acl_id):
    if request.method == 'POST':
        try:
            task = request.POST['task']
            if task == 'usr_group_update':
                user_obj = get_object_or_404(User, pk=acl_id)
                groups = request.POST.getlist('groups')
                user_obj.groups = []
                for iter in groups:
                    group = get_object_or_404(Group, name=iter)
                    user_obj.groups.add(group)
                messages.success(request, 'Database updated successfully')
                return HttpResponseRedirect(reverse('nms:acl_user'))
            elif task == 'ch_per_usr_group':
                group = get_object_or_404(Group, pk=acl_id)
                rights = request.POST.getlist('rights')
                groups_received = request.POST.getlist('groups')
                users_received = request.POST.getlist('users')
                group.permissions = []
                group.user_set.clear()
                for iter in rights:
                    right = iter
                    permission = Permission.objects.get(codename=right)
                    group.permissions.add(permission)
                
                for iter in groups_received:
                    group_recv = get_object_or_404(Group, pk=iter)
                    for item in group_recv.user_set.all():
                        group.user_set.add(item)
                for iter in users_received:
                    user_recv = get_object_or_404(User, pk=iter)
                    group.user_set.add(user_recv)
                
                messages.success(request, 'Database updated successfully')
                return HttpResponseRedirect(reverse('nms:acl_groups_manage', args=(acl_id,)))
            
            elif task == 'dev_group_update':
                device = get_object_or_404(Devices, pk=acl_id)
                groups = request.POST.getlist('groups')
                if Dev_group.objects.filter(devid=device).exists():
                    Dev_group.objects.filter(devid=device).delete()
                for group in groups:
                    group_obj = get_object_or_404(Group, pk=group)
                    Dev_group.objects.get_or_create(gid=group_obj, devid=device)
                messages.success(request, 'Database updated successfully')
                return HttpResponseRedirect(reverse('nms:acl_groups'))    
            
            elif task == 'ch_per_dev_group':
                group = get_object_or_404(Group, pk=acl_id)
                groups_received = request.POST.getlist('groups')
                users_received = request.POST.getlist('users')
                devices = request.POST.getlist('devices')
                rights = request.POST.getlist('rights')
                group.permissions = []
                group.user_set.clear()
                if Dev_group.objects.filter(gid=group).exists():
                    Dev_group.objects.filter(gid=group).delete()
                for iter in devices:
                    dev = Devices.objects.get(pk=iter)
                    Dev_group.objects.get_or_create(gid=group, devid=dev)
                for iter in rights:
                    right = iter
                    right += '_devices'
                    permission = Permission.objects.get(codename=right)
                    group.permissions.add(permission)
                for iter in groups_received:
                    group_recv = get_object_or_404(Group, pk=iter)
                    for item in group_recv.user_set.all():
                        group.user_set.add(item)
                for iter in users_received:
                    user_recv = get_object_or_404(User, pk=iter)
                    group.user_set.add(user_recv)
                messages.success(request, 'Database updated successfully')
                return HttpResponseRedirect(reverse('nms:acl_groups_manage', args=(acl_id,)))
                
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
    
    
    return render(request, 'nms/acl_groups_manage.html', {'devices': devices, 'group':group, 'list_check': list_check, 'manage_check': manage_check, 'change_check': change_check, 'checked': checked, 'dev_check': dev_check,
                                                        'add_user': add_user, 'change_user': change_user, 'delete_user': delete_user, 'list_user': list_user, 'add_group': add_group, 'change_group': change_group, 'delete_group': delete_group, 'list_group': list_group, 'request':request, 'groups_usr': groups_usr, 'users': users, 'groups_dev': groups_dev, 'add_devices': add_devices, 'delete_devices': delete_devices})

@login_required
def acl_groups_handler(request):
    if request.method == 'POST':
        if request.POST['task'] == 'usr':
            name = 'usr:'
            name += request.POST['group']
            Group.objects.get_or_create(name=name)
            messages.success(request, "Database updated succesfully")
            return HttpResponseRedirect(reverse('nms:acl_groups'))
        elif request.POST['task'] == 'dev':
            name = 'dev:'
            name += request.POST['group']
            Group.objects.get_or_create(name=name)
            messages.success(request, "Database updated succesfully")
            return HttpResponseRedirect(reverse('nms:acl_groups'))
        elif request.POST['task'] == 'delete':
            groups = request.POST.getlist('delete')
            for iter in groups:
                group = get_object_or_404(Group, pk=iter)
                if group.name == 'usr:admin' or group.name == 'usr:staff':
                    messages.error(request, "Can't remove group: " + group.name)
                    return HttpResponseRedirect(reverse('nms:acl_groups'))
                group.delete()  
            messages.success(request, "Database updated succesfully")
            return HttpResponseRedirect(reverse('nms:acl_groups'))
        elif request.POST['task'] == 'del_user':
            users = request.POST.getlist('delete')
            for item in users:
                user = get_object_or_404(User, pk=item)
                if user.username == 'root':
                    messages.error(request, "Can't remove user: root")
                    return HttpResponseRedirect(reverse('nms:acl_user'))
                user.delete()
            messages.success(request, "Database updated succesfully")
            return HttpResponseRedirect(reverse('nms:acl_user'))
        
        elif request.POST['task'] == 'del_device':
            devices = request.POST.getlist('delete')
            for item in devices:
                device = get_object_or_404(Devices, pk=item)
                device.delete()
                messages.success(request, "Database updated succesfully")
                return HttpResponseRedirect(reverse('nms:acl_device'))
        
        else:
            messages.error(request, "Some fields are not set")
            return HttpResponseRedirect(reverse('nms:acl_groups'))

@login_required
def permissions(request):
    if request.method == 'GET':
        try:
            per = request.GET['per']
            return HttpResponse('Permission required for: '+ per)
        except KeyError:
            messages.error(request, 'Invalid URL')
            return HttpResponseRedirect(reverse('nms:index'))
    else:
        messages.error(request, 'Invalid URL')
        return HttpResponseRedirect(reverse('nms:index'))

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
		return render(request, 'nms/register.html', {'request':request})
			

def login_handler(request):
	if (request.method == 'GET' and 'next' in request.GET):
		url = request.GET['next']
		return(render(request, 'nms/login.html', {'url': url}))
	else:
		return render(request, 'nms/login.html', {'request':request})

@login_required
def devices(request):
    return render(request, 'nms/devices.html', {'request':request})

@login_required
def devices_manage(request):
    user_obj = request.user
    groups = user_obj.groups.all()
    try:
        groups_list = [x for x in groups if x.permissions.filter(codename='list_devices').exists()]
        dev_group = [x.dev_group_set.all() for x in groups_list][0]
        devices = {x.devid for x in dev_group}
        devices = list(devices)
        if groups_list != []:
    	    return render(request, 'nms/devices_manage.html', {'devices': devices, 'request':request})
        else:
            messages.error(request, "You are not added to any devices yet with the right permission.")
            return HttpResponseRedirect(reverse('nms:index'))
    except IndexError:
        messages.error(request, "You are not added to any groups yet.")
        return HttpResponseRedirect(reverse('nms:index'))

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
			dev = None
			for i in gen_dev:
				if str(i.model_id) == request.POST['selectModel'] and str(i.vendor_id) == request.POST['selectVendor'] and str(i.dev_type_id) == request.POST['selectType']:
					dev = i
			if dev == None:
				return HttpResponseNotFound('<h1>Page not found</h1>')
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
		 'dev_model_view' : dev_model_view, 'os_view': os_view, 'gen_dev': gen_dev, 'request':request})
		
@login_required
def device_manager(request, device_id_request):
	if not passwordstore.hasMasterPassword():
		return HttpResponseRedirect(reverse('nms:init') + '?next=' + reverse('nms:device_manager', args=(device_id_request,)))
	devices = get_object_or_404(Devices, pk=device_id_request)
	if request.method == 'GET' and 'refresh' in request.GET:
		xmlparser.removeTaskCache(xmlparser.get_xml_struct(devices.gen_dev_id.file_location_id.location))
		xmlparser.removeXmlStruct(devices.gen_dev_id.file_location_id.location)
		commands.removeInterfaces(devices)
	root = xmlparser.get_xml_struct(devices.gen_dev_id.file_location_id.location)
	cmd, parser = xmlparser.getInterfaceQuery(root)
	interfaces = commands.getInterfaces(cmd, parser, devices) #Use if the device is online
	#interfaces = ['FastEthernet0/0', 'FastEthernet0/1'] #Use if no connection to the device is possible for dummy interfaces
	if interfaces == -1:
		messages.error(request, 'Failed to connect to device')
		return HttpResponseRedirect(reverse('nms:devices'))

	taskhtml = xmlparser.getAvailableTasksHtml(root, devices.dev_id, interfaces, passwordstore.getEnablePassword(devices))
	return render(request, 'nms/manage_device.html', {'devices': devices, 'taskhtml': taskhtml, 'request':request})

@login_required
def device_modify(request, device_id_request):
	if not passwordstore.hasMasterPassword():
		return HttpResponseRedirect(reverse('nms:init') + '?next=' + reverse('nms:device_modify', args=(device_id_request,)))
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
			device.save()
			passwordstore.storeRemotePassword(device, password_remote)
			passwordstore.storeEnablePassword(device, password_enable)
			messages.success(request, 'Database updated successfully.')
			return HttpResponseRedirect(reverse('nms:device_add', args=(device_id_request,)))
		except (KeyError, ValueError):
			messages.error(request, 'Not all fields are are set or an other error occured')
			return HttpResponseRedirect(reverse('nms:device_add', args=(device_id_request,)))
	else:
		return render(request, 'nms/modify_device.html', {'devices': device, 'gen_dev': gen_dev, 'os_dev': os_dev, 'request':request})

@login_required
def user_settings(request):
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
				else:
					messages.error(request, 'Not all fields were filled')
				return HttpResponseRedirect(reverse('nms:user_settings'))
		except (ValueError, KeyError):
			messages.error(request, 'Not all fields are set or an other error occured')
			return HttpResponseRedirect(reverse('nms:user_settings'))
	return render(request, 'nms/chpasswd.html', {'request':request}, context_instance=RequestContext(request))

@login_required
def send_command(request, device_id_request):
	if request.method == 'GET' and 'command' in request.GET:
		command = request.GET['command']
	else:
		return HttpResponseRedirect(reverse('nms:device_manager', args=(device_id_request,)))
	
	device = Devices.objects.get(pk=device_id_request)
	ret = commands.executeTask(command, device)
	if ret == -1:
		messages.error(request, 'Failed to connect to device')
	else:
		msg_text = ''
		for line in ret:
			msg_text += line + '<br />'
		messages.info(request, msg_text)
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

@login_required
def query(request):
	if request.method == 'GET':
		if 'type' in request.GET and 'q' in request.GET:
			type = request.GET['type']
			query = request.GET['q']
		else:
			return HttpResponse('<Error>', content_type='text/plain')
	else:
		return HttpResponse('<Error>', content_type='text/plain')

	if type == 'models':
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
	elif type == 'ssh':
		if not 'dev' in request.GET:
			return HttpResponse('<Missing dev in GET>', content_type='text/plain')
		dev = request.GET['dev']
		try:
			device = Devices.objects.get(pk=dev)
		except:
			return HttpResponse('<No such device>', content_type='text/plain')
		if query == 'receive':
			connection = commands.getSSHConnection(request.user, device)
			try:
				ret = connection.chan.recv(4096)
			except:
				return HttpResponse('', content_type='text/plain')
			return HttpResponse(ret.decode(), content_type='text/plain')
		elif query == 'send':
			if not 'text' in request.GET:
				return HttpResponse('', content_type='text/plain')
			text = request.GET['text']
			connection = commands.getSSHConnection(request.user, device)
			text = text + '\n'
			connection.chan.send(text.encode())
			return HttpResponse('', content_type='text/plain')
		elif query == 'del':
			commands.removeSSHConnection(request.user, device)
			return HttpResponse('Connection closed', content_type='text/plain')
		elif query == 'priv':
			connection = commands.getSSHConnection(request.user, device)
			text = passwordstore.getEnablePassword(device).decode() + '\n'
			connection.chan.send(text.encode())
			return HttpResponse('', content_type='text/plain')
	return HttpResponse('<Unkown query type>!', content_type='text/plain')

def logout_handler(request):
	logout(request)
	messages.success(request, "You are logged out")
	return HttpResponseRedirect(reverse('nms:login_handler'))

@login_required
def device_ssh(request, device_id_request):
	device = get_object_or_404(Devices, pk=device_id_request)
	return render(request, 'nms/ssh.html', {'device': device, 'request':request})

@login_required
def init(request):
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
	if request.method == 'POST' and 'qtype' in request.POST:
		p = request.POST
		if p['qtype'] == 'add_gendev':
			if 'dev_type' in p and 'vendor' in p and 'model' in p and 'xml_files' in p:
				try:
					Gen_dev(dev_type_id_id=int(p['dev_type']), vendor_id_id=int(p['vendor']), model_id_id=int(p['model']), file_location_id_id=int(p['xml_files'])).save()
				except:
					messages.error(request, 'Error adding device template')
		elif p['qtype'] == 'add_devtype':
			if 'name' in p:
				try:
					Dev_type(dev_type_name=p['name']).save()
				except:
					messages.error(request, 'Error adding device type')
		elif p['qtype'] == 'del_devtype':
			if 'items' in p:
				for i in p['items']:
					try:
						Dev_type.objects.get(pk=int(i)).delete()
					except:
						messages.error(request, 'Error deleting device type')
		elif p['qtype'] == 'add_vendor':
			if 'name' in p:
				try:
					Vendor(vendor_name=p['name']).save()
				except:
					messages.error(request, 'Error adding vendor')
		elif p['qtype'] == 'del_vendor':
			if 'items' in p:
				for i in p['items']:
					try:
						Vendor.objects.get(pk=int(i)).delete()
					except:
						messages.error(request, 'Error deleting vendor')
		elif p['qtype'] == 'add_model':
			if 'name' in p:
				try:
					Dev_model(model_name=p['name']).save()
				except:
					messages.error(request, 'Error adding model')
		elif p['qtype'] == 'del_model':
			if 'items' in p:
				for i in p['items']:
					try:
						Dev_model.objects.get(pk=int(i)).delete()
					except:
						messages.error(request, 'Error deleting model')
		elif p['qtype'] == 'add_xml':
			if 'name' in p:
				try:
					File_location(location=p['name']).save()
				except:
					messages.error(request, 'Error adding XML')
		elif p['qtype'] == 'del_xml':
			if 'items' in p:
				for i in p['items']:
					try:
						File_location.objects.get(pk=int(i)).delete()
					except:
						messages.error(request, 'Error deleting XML')

	dev_types = Dev_type.objects.all()
	vendors = Vendor.objects.all()
	models = Dev_model.objects.all()
	xml_files = File_location.objects.all()
	return render(request, 'nms/manage_gendev.html', {'request':request, 'dev_types':dev_types, 'vendors':vendors, 'models':models, 'xml_files':xml_files})
