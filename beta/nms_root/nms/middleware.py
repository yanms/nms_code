from datetime import datetime, timedelta
from django.conf import settings
from django.contrib import auth

class SessionLogout:
	def process_request(self, request):
		if not request.user.is_authenticated():
			return
		try:
			if datetime.now().timestamp() - request.session['last_touch'] > timedelta(0, settings.SESSION_EXPIRATION_TIME, 0).total_seconds():
				auth.logout(request)
				del request.session['last_touch']
				return
		except KeyError:
			pass
		request.session['last_touch'] = datetime.now().timestamp()