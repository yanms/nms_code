from django import template

register = template.Library()

## menu_tags.py
@register.simple_tag
def active(path, pattern):
	import re
	if re.search(pattern, path):
		return 'active'
	return ''
