Research Notes for Python SSL/TLS related CWE support
==============================================================================

:Version: 0.0 begun 2018-02-07
:Authors:
	Darren P Meyer <dmeyer@veracode.com>
:Tickets:
	Research: RES-2490_ (see `code branch`_),
	BBRD: BBRD-1545_,
	Static: STATIC-16374_,
	Feedback: FEED-1447_

.. _RES-2490: https://jira.veracode.local/jira/browse/RES-2490
.. _code branch: https://gitlab.laputa.veracode.io/research-roadmap/python-multi-tls_flaws/tree/res-2490
.. _BBRD-1545: https://jira.veracode.local/jira/browse/BBRD-1545
.. _STATIC-16374: https://jira.veracode.local/jira/browse/STATIC-16374
.. _FEED-1447: https://jira.veracode.local/jira/browse/FEED-1447

`Research repository`_ on Laputa Gitlab.

.. contents:: Table of Contents
   :backlinks: entry
   :depth: 3

.. footer:: © 2018, CA Veracode. Prepared for Veracode Research


Scope
------------------------------------------------------------------------------

This research aims to approach parity with Java/.NET on finding flaws with CWEs related to SSL/TLS configuration and use. It aims to cover likely SSL/TLS implementation errors.

RES-2490
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

RES-2490_ work covers issues using the following CWEs:

* CWE-295_ Improper Certificate Validation
* CWE-297_ Improper Validation of Certificate with Host Mismatch
* CWE-326_ Inadequate Encryption strength

This CWE coverage is restricted to the Python support we have as of 07. February 2018, which includes:

* The ``ssl`` module of the Python 2 and Python 3 standard libraries (in this doc, stdlib-ssl_ links to the Python 2 version)
* The requests_ module
* The httplib2_ module


Future scope
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* CWE-347_ Improper Verification of Cryptographic Signature [TODO]
* CWE-391_ Unchecked Error Condition [TODO]

.. _CWE-295: https://cwe.mitre.org/data/definitions/295.html
.. _CWE-297: https://cwe.mitre.org/data/definitions/297.html
.. _CWE-326: https://cwe.mitre.org/data/definitions/326.html
.. _CWE-347: https://cwe.mitre.org/data/definitions/347.html
.. _CWE-391: https://cwe.mitre.org/data/definitions/391.html
.. _stdlib-ssl: https://docs.python.org/2/library/ssl.html
.. _requests: http://docs.python-requests.org/en/master/
.. _httplib2: https://pypi.python.org/pypi/httplib2
.. _Research repository:  https://gitlab.laputa.veracode.io/research-roadmap/python-multi-tls_flaws



Problem
------------------------------------------------------------------------------

We can't see common SSL/TLS configuration errors in libraries we support.

Customer Feedback - FEED-1447
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


FEED-1447_ references an open-source project that a customer believes should have triggered a CWE-297_ at `line 62 of web_socket.py <https://github.com/vmware/liota/blob/177d3c6ee6192b8c7863eb64e332ff2d1a304cc2/liota/lib/transports/web_socket.py#L62>`_, but did not. FEED-1447_ was the catalyst for this work, but will likely not be resolved by this work. Mainly because:

* The cited project is using a 3rd-party library (websocket-client_) that is not supported as of 07. Feb. 2018
* The websocket-client_ library asks the stdlib-ssl_ to verify the host name by default, so no CWE-297_ should be reported here -- the customer's assertion appears to be incorrect

There *are* relevant issues here from a conceptual point of view. Specifically, there is a path by which a CWE-295_ should be reported by a consuming application (if we supported this library), because there is `a path to not verify the SSL/TLS certificate at all <https://github.com/vmware/liota/blob/177d3c6ee6192b8c7863eb64e332ff2d1a304cc2/liota/lib/transports/web_socket.py#L65>`_.

.. _websocket-client: https://pypi.python.org/pypi/websocket-client

The customer appears to be incorrect
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

While a consumer of the `supposedly problematic function <https://github.com/vmware/liota/blob/177d3c6ee6192b8c7863eb64e332ff2d1a304cc2/liota/lib/transports/web_socket.py#L62>`_ could specify an ``sslopts`` that prevented valid host name comparison, or prevent the certificate from being validated in any way by setting ``verify=False``, neither of these are the default behavior.

The ``sslopts`` argument *is* propagated, eventually, to stdlib-ssl_ and the Python ``sockets`` library, so at most we would be marking these as potential propagators were we to add support for websocket-client_.



Roadmap direction - BBRD-1545
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

BBRD-1545_ describes better support for SSL/TLS consumer implmentation errors in Python scanning support. This is relevant not only to improve current Python 2 scanner support but also as we plan Python 3 support. The main emphasis, therefore, is on finding the flaws (as specified in Scope_, above) associated with risky use of the stdlib-ssl_ module.

There is an additional emphasis on ensuring that we find similar flaws that are propagated by our supported libraries requests_ and httplib2_. There is potentially future scope for examining other supported libraries to see if there are SSL/TLS consumer flaws likely to exist in them as well; however, that would require an extensive support review and is probably best customer-led.


Spec
------------------------------------------------------------------------------

Herein lies the spec for various modules' TLS support

Module ``ssl``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Tests are in ``src/test-stdlib_ssl/tls_tests`` ; the entry point should be ``__main__.py``**

The stdlib-ssl_ module can be used in a client or server mode. There are a few correct ways to use it in each mode, and a few clear error paths. There's a lot of gray area in between.

There are subtle differences between even minor ``python`` release versions, so all guidance here targets:

* Python 2.7.9
* Python 3.4

Newer python versions have corrections and security improvements.

Correct, standard client usage example can be found in the ``safe_tls_connect`` function in ``libssl_connect.py`` in the

All SSL operations have to create an ``SSLContext`` to configure how SSL will behave, and an ``SSLSocket`` to handle the actual network communication. An ``SSLSocket`` wraps a stdlib socket_.socket with an ``SSLContext`` so that handshakes and SSL comms can occur.

So the process in detail is:

1. Create the ``SSLContext``
2. Configure the context
3. Use the context to wrap a socket into an ``SSLSocket``
4. Examine the SSL configuration on the remote host
5. Do an SSL handshake
6. Work with the connection
7. Close the connection

There are some shortcuts. ``create_default_context()`` does the first two steps (though you can do some more configuration if you wish). ``connect()`` handles steps 4 and 5 with reasonable defaults.

**Safe examples are in ``libssl_connect_safe.py``**

.. _socket: https://docs.python.org/2/library/socket.html


Gotchas: things to watch out for when building support/scrub policy
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

* Weak cipher support is going to be a little hinky, and is really focused on removing RC4 and 3DES. If people specify their own cipher string, I'd expect a mix of FPs and FNs depending on how they do it -- FP when RC4/3DES aren't explicitly named as excluded but are still not present in the list, FN when the cipher list has stupid stuff in it other than RC4/3DES. Given that cipher support is specified as an OpenSSL-style *string*, and the current settings are not easily inspectable in the ``SSLContext`` object, this is going to be challenging to improve support for

* There are two ``wrap_socket()`` functions: ``SSLContext.wrap_socket()`` is flexible and relatively easy to determine safe use of, since you can look at how the ``SSLContext`` object was configured. ``ssl.wrap_socket()`` creates an ``SSLContext`` on the fly, which is much easier to have in a misconfigured state. We should consider ``ssl.wrap_socket()`` a banned function because of how easy it is to screw up -- we should ask devs to set up an ``SSLContext`` (ideally by using ``ssl.create_default_context()``) and use ``SSLContext.wrap_socket()`` instead.

* Flaws are annotated on ``SSLSocket.connect()`` calls for clients and ``SSLSocket.bind()`` for servers, because a bad configuration isn't actually a flaw until you use it to connect. But the configuration will be what actually needs adjusting.

* As of RES-2490_, **there is no support for things specific to SSL servers**. There's a lot of overlap, so we still support servers, but there's not support for things you can only get wrong with servers.

* As of RES-2490_, **there is no support for flaws that result from using SSL sockets with multiprocessing/multithreading**. There are definitely ways to screw that up, because threading/forking messes with the PRNG if you aren't careful; we just aren't building support for it right now because it isn't commonly in use and it's _hard_.

CWE-297 in ``ssl``
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

**Test functions are in ``libssl_connect_disable_checkhostname.py``**

In Python 2's stdlib-ssl_, ``create_default_context()`` has the following notes:

    Changed in version 2.7.10: RC4 was dropped from the default cipher string.

    Changed in version 2.7.13: ChaCha20/Poly1305 was added to the default cipher string, 3DES was dropped from the default cipher string.

    Changed in version 2.7.15: TLS 1.3 cipher suites TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and TLS_CHACHA20_POLY1305_SHA256 were added to the default cipher string.

And for Python 3:

    Changed in version 3.4.4: RC4 was dropped from the default cipher string.

    Changed in version 3.6: ChaCha20/Poly1305 was added to the default cipher string.

    3DES was dropped from the default cipher string.

    Changed in version 3.6.3: TLS 1.3 cipher suites TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, and TLS_CHACHA20_POLY1305_SHA256 were added to the default cipher string.

**Because of these varying defaults, we will have to raise an informational flaw when default ciphers are used, along the lines of "if you're using  < 2.7.15 you should add the following ciphers" or "if you're using < 2.7.10 you should remove RC4 manually".**


CWE-295 in ``ssl``
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

**Test functions are in ``libssl_connect_cert_disabled.py``**

When using ``create_default_context()``, cert-checking is enabled by default, but can be disabled by setting ``SSLContext.cert_mode`` to ``ssl.CERT_NONE``.

When creating an ``SSLContext`` manually, either through the constructor or through ``ssl.wrap_socket()`` (do not confuse with ``SSLContext.wrap_socket()``!)

CWE-326 in ``ssl``
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

**Test functions are in ``libssl_connect_oldssl.py`` (old SSL versions) and ``libssl_connect_weak_cipher.py`` (weak cipher spec)**

SSLv2 and SSLv3 are security risks and shouldn't be used.

When using ``create_defalt_context()`` in 2.7.9/3.4 or newer, old SSL versions (SSLv2 and SSLv3) are disabled by default, but they can be turned on by doing an ``&=`` operation to remove ``ssl.OP_NO_SSLv2`` and/or ``ssl.OP_NO_SSLv3`` from the options. The boolean logic here is important to get right; notice in the test that ``options`` is being combined with the *binary not* of those ``OP_*`` items. If they aren't being "NOT-ed", then those protocols are actually being *disabled* which is the correct/safe configuration.

When creating an ``SSLContext`` manually, those SSL versions need to be manually *disabled* by using an ``|=`` with the relevant ``ssl.OP_NO_*`` constants. See the safe examples for how this looks. Failing to disable them should produce a flaw.

While some newer pythons have a better default cipher string, we're reporting any flaw that would be present in 2.7.9/3.4; as a result, we expect the string to be manually set (see the safe examples) in the ``SSLContext``. This flaw should be set lower severity, though, since it will frequently be marked as mitigated when customers can guarantee a version of Python that doesn't have a weak cipher string. We can't reliably statically determin if they're doing that.

CWE-676 in ``ssl``
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

**Test functions are in ``libssl_connect_banned_wrap.py``**

The ``ssl.wrap_socket()`` function (don't confuse with ``SSLContext.wrap_socket()``!) generates a default ``SSLContext`` and binds it to a socket in one step. While it's *possible* to pass enough configuration to ``ssl.wrap_socket()`` to do this safely, it's so difficult to do so (in target Python versions, at least) that it's extremely error-prone.

We recommend setting up and configuring an ``SSLContext`` (preferably through ``create_default_context()`` and some additional configuration, see the safe examples) and then using ``SSLContext.wrap_socket()`` instead.


Module ``httplib``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The httplib_ module (Python 3 uses `http.client`_ namespace, but it's substantially the same module) is a simplified HTTP connection module

**Tests are in src/test-httplib**

It uses the ``ssl`` module under the hood, so all above CWEs apply, they just result from calling the ``request`` or ``connect`` methods of ``HTTPSConnection`` when the object is using a weak ``context`` configuration.  If the ``context`` argument isn't supplied during construction, it's just like connecting with ``ssl.create_default_context()``.

You can think of ``connect()`` and ``request()`` as additional "sinks" along with ``SSLSocket.connect()``. The test suite here is minimal, and should be used just to verify that those methods serve that purpose.



