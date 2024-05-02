from libssl_connect import *


def cwe676_tls_connect_sslwrapsocket(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """CWE-676 (dangerous function that _could_ be used safely, but not likely)

    ``ssl.wrap_socket()`` is very difficult to use safely, since it makes it nearly impossible
    to configure the underlying ``SSLContext`` properly. Developers should set up an
    ``SSLContext`` and then use ``SSLContext.wrap_socket()`` instead.

    """
    ssl_socket = ssl.wrap_socket(socket.socket(socket.AF_INET))  # CWEID 676

    # attempt the connection. As of 2.7.9, when context.set_hostname is True,
    # calling .connect() will verify the hostname.
    ssl_socket.connect((hostname, port))
    return ssl_socket
