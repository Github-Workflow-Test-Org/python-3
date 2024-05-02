from libssl_connect import *


def cwe326_tls_connect_weak_ciphers_not_excluded(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Exercise CWE-326 (Inadequate encryption strength) by failing to exclude weak ciphers

    While later versions of Python remove unsafe ciphers, we are targeting 2.7.9 as an assumption. Therefore,
    developers should be excluding RC4 and 3DES explicitly; failing to do so is CWE-326. Ideally, we should
    be able to explain why we alert on this and recommend mitigation if a version of 2.7.13 is guaranteed in
    the production environment

    See ``safe_tls_connect()`` for correct configuration

    """
    ssl_context = ssl.create_default_context(cafile=cafile)

    ssl_socket = ssl_context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname)

    # SCRUB: look for custom-set SSLContext.set_ciphers() calls that may be correct, or this may trigger FPs
    ssl_socket.connect((hostname, port))  # CWEID 326
    return ssl_socket


def cwe326_tls_connect_weak_ciphers_not_excluded_manual(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Exercise CWE-326 (Inadequate encryption strength) by failing to exclude weak ciphers

    While later versions of Python remove unsafe ciphers, we are targeting 2.7.9 as an assumption. Therefore,
    developers should be excluding RC4 and 3DES explicitly; failing to do so is CWE-326. Ideally, we should
    be able to explain why we alert on this and recommend mitigation if a version of 2.7.13 is guaranteed in
    the production environment

    See ``safe_tls_connect()`` for correct configuration

    """
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # in newer Pythons, ssl.PROTOCOL_TLS is the same
    ssl_context.options |= ssl.OP_NO_SSLv2  # required to disable SSL 2.x
    ssl_context.options |= ssl.OP_NO_SSLv3  # required to disable SSL 3.x

    ssl_context.verify_mode = ssl.CERT_REQUIRED  # ssl.CERT_OPTIONAL is ok too
    ssl_context.check_hostname = True
    ssl_context.load_verify_locations(cafile)

    # noted that weak ciphers aren't excluded

    ssl_socket = ssl_context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname)

    # SCRUB: look for custom-set SSLContext.set_ciphers() calls that may be correct, or this may trigger FPs
    ssl_socket.connect((hostname, port))  # CWEID 326
    return ssl_socket