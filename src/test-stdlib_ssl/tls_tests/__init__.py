
def connect_with(connector=None, host='localhost', port=443, cafile=None):
    """Tries to make a TLS/SSL connection using ``connector``

    ``connector`` must accept hostname, port, and cafile; it may specify defaults
    for these, and *must* use system CA cert chain if ``cafile`` is ``None``

    Args:
        connector callable: function that returns an SSLSocket
    Return:
        SSLSocket: a socket with a completed handshake
    """

    tls_socket = connector(hostname=host, port=port, cafile=cafile)

    # TODO do stuff with the socket
    return tls_socket
