# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Common constants and global variables.
"""

MSG_DISCONNECT, MSG_IGNORE, MSG_UNIMPLEMENTED, MSG_DEBUG, MSG_SERVICE_REQUEST, \
    MSG_SERVICE_ACCEPT = range(1, 7)
MSG_KEXINIT, MSG_NEWKEYS = range(20, 22)
MSG_USERAUTH_REQUEST, MSG_USERAUTH_FAILURE, MSG_USERAUTH_SUCCESS, \
        MSG_USERAUTH_BANNER = range(50, 54)
MSG_USERAUTH_PK_OK = 60
MSG_USERAUTH_INFO_REQUEST, MSG_USERAUTH_INFO_RESPONSE = range(60, 62)
MSG_GLOBAL_REQUEST, MSG_REQUEST_SUCCESS, MSG_REQUEST_FAILURE = range(80, 83)
MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_SUCCESS, MSG_CHANNEL_OPEN_FAILURE, \
    MSG_CHANNEL_WINDOW_ADJUST, MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA, \
    MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE, MSG_CHANNEL_REQUEST, \
    MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE = range(90, 101)


class FakeLong(int):
    def __new__(cls, v):
        return super(FakeLong, cls).__new__(cls, v)

# for debugging:
MSG_NAMES = {
    MSG_DISCONNECT: b'disconnect',
    MSG_IGNORE: b'ignore',
    MSG_UNIMPLEMENTED: b'unimplemented',
    MSG_DEBUG: b'debug',
    MSG_SERVICE_REQUEST: b'service-request',
    MSG_SERVICE_ACCEPT: b'service-accept',
    MSG_KEXINIT: b'kexinit',
    MSG_NEWKEYS: b'newkeys',
    30: b'kex30',
    31: b'kex31',
    32: b'kex32',
    33: b'kex33',
    34: b'kex34',
    MSG_USERAUTH_REQUEST: b'userauth-request',
    MSG_USERAUTH_FAILURE: b'userauth-failure',
    MSG_USERAUTH_SUCCESS: b'userauth-success',
    MSG_USERAUTH_BANNER: b'userauth--banner',
    MSG_USERAUTH_PK_OK: b'userauth-60(pk-ok/info-request)',
    MSG_USERAUTH_INFO_RESPONSE: b'userauth-info-response',
    MSG_GLOBAL_REQUEST: b'global-request',
    MSG_REQUEST_SUCCESS: b'request-success',
    MSG_REQUEST_FAILURE: b'request-failure',
    MSG_CHANNEL_OPEN: b'channel-open',
    MSG_CHANNEL_OPEN_SUCCESS: b'channel-open-success',
    MSG_CHANNEL_OPEN_FAILURE: b'channel-open-failure',
    MSG_CHANNEL_WINDOW_ADJUST: b'channel-window-adjust',
    MSG_CHANNEL_DATA: b'channel-data',
    MSG_CHANNEL_EXTENDED_DATA: b'channel-extended-data',
    MSG_CHANNEL_EOF: b'channel-eof',
    MSG_CHANNEL_CLOSE: b'channel-close',
    MSG_CHANNEL_REQUEST: b'channel-request',
    MSG_CHANNEL_SUCCESS: b'channel-success',
    MSG_CHANNEL_FAILURE: b'channel-failure'
    }


# authentication request return codes:
AUTH_SUCCESSFUL, AUTH_PARTIALLY_SUCCESSFUL, AUTH_FAILED = range(3)


# channel request failed reasons:
(OPEN_SUCCEEDED,
 OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
 OPEN_FAILED_CONNECT_FAILED,
 OPEN_FAILED_UNKNOWN_CHANNEL_TYPE,
 OPEN_FAILED_RESOURCE_SHORTAGE) = range(0, 5)


CONNECTION_FAILED_CODE = {
    1: 'Administratively prohibited',
    2: 'Connect failed',
    3: 'Unknown channel type',
    4: 'Resource shortage'
}


DISCONNECT_SERVICE_NOT_AVAILABLE, DISCONNECT_AUTH_CANCELLED_BY_USER, \
    DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 7, 13, 14

from Crypto import Random

# keep a crypto-strong PRNG nearby
rng = Random.new()

import sys, logging


DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL

# Common IO/select/etc sleep period, in seconds
io_sleep = 0.01
