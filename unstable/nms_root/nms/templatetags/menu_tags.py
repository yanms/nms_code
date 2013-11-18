## menu_tags.py
@register.simple_tag
def active(request, pattern):
	import re
	if re.search(pattern, request.path):
		return 'active'
	return ''

<!-- navigation -->

{% load menu_tags %}
<ul class="tabset buttons">
	<li class="{% active request "^/$" %}">
		<a href="/" class="ico4"><span>Dashboard</span><em></em></a>
		<span class="tooltip"><span>Dashboard</span></span>
	</li>
	<li class="{% active request "^/devices/" %}">
		<a href="/devices" class="ico1"><span>Devices</span><em></em></a>
		<span class="tooltip"><span>Devices</span></span>
	</li>
	<li class="{% active request "^/devices/add/" %}">
		<a href="/devices/add" class="ico7"><span>Add Device</span><em></em></a>
		<span class="tooltip"><span>Add Device</span></span>
	</li>
	<li class="{% active request "^/acl/" %}">
			<a href="/acl" class="ico5"><span>ACL</span><em></em></a>
			<span class="tooltip"><span>ACL</span></span>
		</li>
	<li class="{% active request "^/settings/" %}">
		<a href="/settings" class="ico8"><span>User Settings</span><em></em></a>
		<span class="tooltip"><span>User Settings</span></span>
	</li>
</ul>
