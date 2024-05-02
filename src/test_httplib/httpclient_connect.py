from http.client import HTTPSConnection
import ssl


def safe_connect(host, port, cafile=None):
    context = ssl.create_default_context(cafile=cafile)
    context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')

    conn = HTTPSConnection(host, port, context=context)

    # test the connection
    conn.connect()
    return conn


def cwe295_connect(host, port, cafile=None):
    context = ssl.create_default_context(cafile=cafile)
    context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')
    context.check_hostname = False  # part of the CWE-297
    context.verify_mode = ssl.CERT_NONE  # part of the CWE-295

    conn = HTTPSConnection(host, port, context=context)

    # test the connection
    conn.connect()  # CWEID 295  # CWEID 297
    return conn