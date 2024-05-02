import ssl
import socket

DEFAULT_TLS_HOST = 'localhost'
DEFAULT_TLS_PORT = 8443

# TODO should there be a CWE for tainted values in cafile= and related arguments?
# TODO support for ssl.wrap_socket instead of just SSLContext.wrap_socket



