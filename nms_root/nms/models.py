from django.db import models

#Valdiaiton needs to be implemented

class vendor(models.Model):
	vendor_id = models.AutoField(primary_key=True)
	vendor_name = models.CharField(max_length=255)
	
	def __str__(self):
		return self.vendor_name

class os_type(models.Model):
	os_type_id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=255)
	
	def __str__(self):
		return self.type

class os(models.Model):
	os_id = models.AutoField(primary_key=True)
	vendor_id = models.ForeignKey(vendor)
	os_type_id = models.ForeignKey(os_type)
	build = models.CharField(max_length=255)
	short_info = models.CharField(max_length=255)
	name = models.CharField(max_length=255)
	
	def __str__(self):
		return self.name + ' ' + self.build

class dev_model(models.Model):
	model_id = models.AutoField(primary_key=True)
	model_name = models.CharField(max_length=255)
	version = models.CharField(max_length=255)
	
	def __str__(self):
		return self.model_name + ' ' + self.version

class dev_type(models.Model):
	dev_type_id = models.AutoField(primary_key=True)
	dev_type_name = models.CharField(max_length=255)
	
	def __str__(self):
		return self.dev_type_name

class gen_dev(models.Model):
	gen_dev_id = models.AutoField(primary_key=True)
	vendor_id = models.ForeignKey(vendor)
	model_id = models.ForeignKey(dev_model)
	dev_type_id = models.ForeignKey(dev_type)
	
	def __str__(self):
		return self.vendor_id + ' ' + self.model_id #Making use of the defined __str__ methods of these classes

class os_dev(models.Model):
	os_dev_id = models.AutoField(primary_key=True)
	os_id = models.ForeignKey(os)
	gen_dev_id = models.ForeignKey(gen_dev)

	def __str__(self):
		return self.os_id + ' ' + self.gen_dev_id
	
class devices(models.Model):
	dev_id = models.AutoField(primary_key=True)
	gen_dev_id = models.ForeignKey(gen_dev)
	os_dev_id = models.ForeignKey(os_dev)
	ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=False)
	ip_version = models.PositiveIntegerField()
	port = models.PositiveIntegerField()
	login_name = models.CharField(max_length=255)
	password_remote = models.CharField(max_length=255)
	password_enable = models.CharField(max_length=255)
	pref_remote_prot = models.CharField(max_length=255, default='ssh')
	
	def __str__(self):
		return self.gen_dev_id + ' - ' + self.ip

class user(models.Model):
	user_id = models.AutoField(primary_key=True)
	username = models.CharField(max_length=255)
	first_name = models.CharField(max_length=255)
	last_name = models.CharField(max_length=255)
	password = models.CharField(max_length=255)
	is_active = models.BooleanField(default=False)
	mode = models.PositiveIntegerField(default = '0')
	
	def __str__(self):
		return self.username

class roles(models.Model):
	roles_id = models.AutoField(primary_key=True)
	user_id = models.ForeignKey(user)
	dev_id = models.ForeignKey(devices)

	def __str__(self):
		return self.user_id + ': ' + self.dev_id
