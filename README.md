# Certificates

Just a quick and simple OpenSSL POC to help create certificates from the CLI. *No Zen!*

Uses subprocess.Popen() or the more recent wrapper, subprocess.run() to run the well known OpenSSL command to create various certs.

Some attempt to add configuration to an openssl.cnf is made. Custom cfg is used for specific requirements.

Yes, using https://cryptography.io/en/latest/ is a preferred solution but simply looking to automate standard openssl
to add certs to Apache webservers etc.
