from django.contrib import admin
from nms.models import OS, OS_type, Dev_model, Gen_dev, Dev_type, Vendor, OS_dev, Roles, User, Devices

admin.site.register(OS)
admin.site.register(OS_type)
admin.site.register(Dev_model)
admin.site.register(Gen_dev)
admin.site.register(Dev_type)
admin.site.register(Vendor)
admin.site.register(OS_dev)
admin.site.register(Roles)
admin.site.register(User)
admin.site.register(Devices)
