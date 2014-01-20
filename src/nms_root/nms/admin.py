"""
Registration for the built-in django admin module. This can be used as an alternative
method of manipulating the database.

Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2 of the License, or (at your option) 
any later version.
"""

from django.contrib import admin
from nms.models import OS, OS_type, Dev_model, Gen_dev, Dev_type, Vendor, OS_dev, Devices, File_location, History, Settings, Dev_group
from django.contrib.auth.models import Permission

admin.site.register(OS)
admin.site.register(OS_type)
admin.site.register(Dev_model)
admin.site.register(Gen_dev)
admin.site.register(Dev_type)
admin.site.register(Vendor)
admin.site.register(OS_dev)
admin.site.register(Devices)
admin.site.register(File_location)
admin.site.register(History)
admin.site.register(Settings)
admin.site.register(Dev_group)
admin.site.register(Permission)
