from django import template
from django.core.urlresolvers import reverse
import re

register = template.Library()

@register.simple_tag
def active(request, pattern):
    if pattern == '/':
        pattern += '$'
    if re.search(pattern, request.path):
        return 'active'
    return ''
