from django.db import models
from django.contrib.auth.models import User, Group

#Validation needs to be implemented
app_label = 'nms'

class Vendor(models.Model):
	vendor_id = models.AutoField(primary_key=True)
	vendor_name = models.CharField(max_length=255)
	
	def __str__(self):
		return self.vendor_name

class OS_type(models.Model):
	os_type_id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=255)
	
	def __str__(self):
		return self.type

class OS(models.Model):
	os_id = models.AutoField(primary_key=True)
	vendor_id = models.ForeignKey(Vendor, on_delete=models.PROTECT)
	os_type_id = models.ForeignKey(OS_type, on_delete=models.PROTECT)
	build = models.CharField(max_length=255)
	short_info = models.CharField(max_length=255)
	name = models.CharField(max_length=255)
	
	def __str__(self):
		return str(self.os_type_id) + ' - ' + str(self.name) + ' ' + str(self.build)

class Dev_model(models.Model):
	model_id = models.AutoField(primary_key=True)
	model_name = models.CharField(max_length=255)
	version = models.CharField(max_length=255)
	
	def __str__(self):
		return str(self.model_name) + ' ' + str(self.version)

class Dev_type(models.Model):
	dev_type_id = models.AutoField(primary_key=True)
	dev_type_name = models.CharField(max_length=255)
	
	def __str__(self):
		return self.dev_type_name

class File_location(models.Model):
    file_location_id = models.AutoField(primary_key=True)
    location = models.CharField(max_length=255)

class Gen_dev(models.Model):
	gen_dev_id = models.AutoField(primary_key=True)
	vendor_id = models.ForeignKey(Vendor, on_delete=models.PROTECT)
	model_id = models.ForeignKey(Dev_model, on_delete=models.PROTECT)
	dev_type_id = models.ForeignKey(Dev_type, on_delete=models.PROTECT)
	file_location_id = models.ForeignKey(File_location, on_delete=models.PROTECT)

	def __str__(self):
		return str(self.dev_type_id) + ' ' + str(self.vendor_id) + ' ' + str(self.model_id) #Making use of the defined __str__ methods of these classes
	
class OS_dev(models.Model):
	os_dev_id = models.AutoField(primary_key=True)
	os_id = models.ForeignKey(OS, on_delete=models.PROTECT)
	gen_dev_id = models.ForeignKey(Gen_dev, on_delete=models.PROTECT)

	def __str__(self):
		return str(self.gen_dev_id) + ' ' + str(self.os_id)
	
class Devices(models.Model):
	dev_id = models.AutoField(primary_key=True)
	gen_dev_id = models.ForeignKey(Gen_dev, on_delete=models.PROTECT)
	os_dev_id = models.ForeignKey(OS_dev, on_delete=models.PROTECT)
	ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=False)
	ip_version = models.PositiveIntegerField()
	port = models.PositiveIntegerField(default=22)
	login_name = models.CharField(max_length=255)
	password_remote = models.CharField(max_length=255)
	password_enable = models.CharField(max_length=255)
	pref_remote_prot = models.CharField(max_length=255, default='ssh')
	
	def __str__(self):
		return str(self.gen_dev_id) + ' - ' + str(self.ip)


class History(models.Model):
    history_id = models.AutoField(primary_key=True)
    action = models.CharField(max_length=255)
    action_type = models.CharField(max_length=255, blank=True, null=True)
    dev_id = models.ForeignKey(Devices, blank=True, null=True)
    user_id = models.ForeignKey(User, blank=True, null=True)
    user_performed_task = models.ForeignKey(User, related_name='user_performed_task', blank=True, null=True)
    date_time = models.DateTimeField()
    group_id = models.ForeignKey(Group, blank=True, null=True)
    
class Settings(models.Model):
    settings_id = models.AutoField(primary_key=True)
    known_id = models.PositiveIntegerField()
    known_name = models.CharField(max_length=255)
    known_boolean = models.BooleanField()
    string = models.CharField(max_length=255)

class Dev_group(models.Model):
    dev_group_id = models.AutoField(primary_key=True)
    gid = models.ForeignKey(Group, on_delete=models.PROTECT)
    devid = models.ForeignKey(Devices, on_delete=models.PROTECT)
    
    def __str__(self):
        return str(self.gid) + ' ' + str(self.devid)

