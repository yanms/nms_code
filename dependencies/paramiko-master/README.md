[![Build Status](https://travis-ci.org/nischu7/paramiko.png)](https://travis-ci.org/nischu7/paramiko)

=======================
paramiko (for Python 3)
=======================

fork of https://github.com/paramiko/paramiko

- Paramiko: Python SSH module
- Copyright: Copyright (c) 2003-2009  Robey Pointer <robeypointer@gmail.com>
- Copyright: Copyright (c) 2013  Jeff Forcier <jeff@bitprophet.org>
- License: LGPL
- Homepage: https://github.com/paramiko/paramiko/
- API docs: http://docs.paramiko.org


What
----

"paramiko" is a combination of the esperanto words for "paranoid" and
"friend".  it's a module for python 3.2+ that implements the SSH2 protocol
for secure (encrypted and authenticated) connections to remote machines.
unlike SSL (aka TLS), SSH2 protocol does not require hierarchical
certificates signed by a powerful central authority. you may know SSH2 as
the protocol that replaced telnet and rsh for secure access to remote
shells, but the protocol also includes the ability to open arbitrary
channels to remote services across the encrypted tunnel (this is how sftp
works, for example).

it is written entirely in python (no C or platform-dependent code) and is
released under the GNU LGPL (lesser GPL). 

the package and its API is fairly well documented in the "doc/" folder
that should have come with this archive.


Requirements
------------

  - python 3.2 or better (as this fork currently supports py3k only) <http://www.python.org/>
  - pycrypto 2.6 or better <https://www.dlitz.net/software/pycrypto/>
  - ecdsa <https://github.com/warner/python-ecdsa>

If you have setuptools, you can build and install paramiko and all its
dependencies with this command (as root):

    easy_install ./


Use
---

the demo scripts are probably the best example of how to use this package.
there is also a lot of documentation, generated with epydoc, in the doc/
folder.  point your browser there.  seriously, do it.  mad props to
epydoc, which actually motivated me to write more documentation than i
ever would have before.

there are also unit tests here::

    $ python ./test.py

which will verify that most of the core components are working correctly.
