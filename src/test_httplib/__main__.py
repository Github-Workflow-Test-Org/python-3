from __future__ import print_function
try:
    from test_httplib import httplib_connect as htconn
except ImportError:
    from test_httplib import httpclient_connect as htconn

from pytest_livehttps import LiveHTTPS_Server, mk_ssl_context, create_self_certificate

import os
import ssl

# setup a cert pair
(cert, key) = create_self_certificate('good')

# Start a server
server = LiveHTTPS_Server(ssl_context=mk_ssl_context(cert, key), port=8443)
server.run()

print(htconn.__name__)

htconn.safe_connect('localhost', 8443, cafile=cert)

conn = htconn.cwe295_connect('localhost', 8443, cafile=cert)
conn.request('GET', '/')  # CWEID 295  # CWEID 297
resp = conn.getresponse()
print(resp.status)
for h in resp.getheaders():
    print(h)


server.stop()
for f in (cert, key):
    os.unlink(f)