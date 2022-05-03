# Certificates

Just a quick and simple OpenSSL POC to help create certificates from the CLI. *No Zen!*

Uses subprocess.Popen() or the more recent wrapper, subprocess.run() to run the well known OpenSSL command to create various certs.

Some attempt to add configuration and edit to an openssl.cnf is made. Custom cfg is used for specific requirements.

Yes, using https://cryptography.io/en/latest/ is a preferred solution but simply looking to automate standard openssl
to add certs to Apache webservers etc.

Code is very process oriented and becoming unwieldy. Probably as a result of blindly following a blog.
Needs to be rationalized using **kwargs around 3 common functions to produce

1. Keys
2. CSR
3. Certificates

and logic in the functions that discern between the type of certificate using the kwarg
i.e. RSA, ECC, CA, Self, Server.

Can now start further rationalization and simplification of repeating code from v1.0 onwards :-)

This is leading to classes and O-O.

Theoretically all the logic could be entered in the config.ini and then a simple python call is made!

