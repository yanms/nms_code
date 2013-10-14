from django.contrib import admin
from nms.models import os, os_type, dev_model, gen_dev, dev_type, vendor, os_dev, roles, user, devices

admin.site.register(os)
admin.site.register(os_type)
admin.site.register(dev_model)
admin.site.register(gen_dev)
admin.site.register(dev_type)
admin.site.register(vendor)
admin.site.register(os_dev)
admin.site.register(roles)
admin.site.register(user)
admin.site.register(devices)
