from django.conf.urls import patterns, url

from nms import views

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^register$', views.register, name='register'),
    url(r'^login/$', views.login_handler, name='login_handler'),
    url(r'^devices/$', views.devices, name='devices'),
    url(r'^devices/add/$', views.device_add, name='device_add'),
    url(r'^devices/(?P<device_id_request>\d+)/manage/$', views.device_manager, name='device_manager'),
    url(r'^devices/(?P<device_id_request>\d+)/modify/$', views.device_modify, name='device_modify'),
	url(r'^devices/(?P<device_id_request>\d+)/command_handler$', views.send_command, name='device_command_handler'),
    url(r'^settings/$', views.user_settings, name='user_settings'),
    url(r'^acl/$', views.acl, name='acl'),
    url(r'^acl/list$', views.acl_list, name='acl_list'),
    url(r'^acl/(?P<acl_user>\d+)/manage$', views.acl_user_manage, name='acl_user_manage'),
    url(r'^session/$', views.session_handler, name='session_handler'),
    url(r'^logout/$', views.logout_handler, name='logout_handler'),
)
