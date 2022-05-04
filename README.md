# Certificates

Just a quick and simple OpenSSL POC to help automatically create certificates from the CLI. *No Zen!*

Likely uses are for test labs where mutual TLS authentication is required on several test client-server hosts.
Creates 2 types of CA, Root with RSA and an ECC to sign certs. For a live lab, comment as required as I haven't time to make menu or gui :-)

Uses subprocess.Popen() or the more recent wrapper, subprocess.run() to run the well known OpenSSL command to create various certs.
This allows for a non-interactive script that facilitates running up hundreds of mutual tls client/server hosts.

Some attempt to add configuration and edit the appropriate openssl.cnf is made. Although this has become cumbersome.
Custom cfg is used for specific requirements. A more suitable solution may be to run a module as standalone. This can easily be crafted from here.

Yes, using https://cryptography.io/en/latest/ is a preferred solution but simply looking to automate standard openssl
to add certs to Apache webservers etc.

Code is very process oriented and becoming unwieldy as it is tying to do too many procedures. But at least nothing is too hardcoded! This is probably as a result of blindly following a blog.
Needs to be rationalized using **kwargs around 3 common functions to produce

1. Keys
2. CSR
3. Certificates

and logic in the functions that discern between the type of certificate or if key has a passphrase using the kwarg
i.e. RSA, ECC, CA, Self, Server.

Can now start further rationalization and simplification of repeating code from v1.0 onwards :-)

This is leading to classes and O-O.

Theoretically all the logic could be entered in the config.ini and then a simple python call is made!

