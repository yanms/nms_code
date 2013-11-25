from django import template
from django.core.urlresolvers import reverse
import re

register = template.Library()

@register.simple_tag
def active(request, pattern):
    if pattern == '/':
        pattern = '^' + pattern + '$'
        print(request.path)
    if re.match(pattern, request.path):
        print(request.path)
        return 'active'
    return ''
