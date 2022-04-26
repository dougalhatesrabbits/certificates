import os

import create_selfSignedCert
import create_selfSignedCert_noenc
import create_ECC_CA_Cert

TODO: "Encrypt log file possibly. Private keys are password protected with encrypted password file though. " \
      "Only relevant for non password protected key option!"

# Working area
projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")

# Self-Signed/CA
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
caKey = os.path.join(privateFolder, "ec-cakey.pem")
caCertificate = os.path.join(certsFolder, "ec-cacert.pem")
ca_opensslConf = os.path.join(baseTlsLocation, "ca_cert.cnf")
selfKey = os.path.join(privateFolder, "self.key")
selfCertificate = os.path.join(certsFolder, "self.crt")
selfCSR = os.path.join(certsFolder, "self.csr")
selfKeyNoEnc = os.path.join(privateFolder, "self-noenc.key")
selfCSRNoEnc = os.path.join(certsFolder, "self-noenc.csr")
selfCertificateNoEnc = os.path.join(certsFolder, "self-noenc.crt")
self_opensslConf = os.path.join(baseTlsLocation, "self_signed_certificate.cnf")
serialFile = os.path.join(baseTlsLocation, "serial")
indexFile = os.path.join(baseTlsLocation, "index.txt")

# Server
serverFolder = os.path.join(baseTlsLocation, "server_certs")
serverKey = os.path.join(privateFolder, "server.key")
serverCSR = os.path.join(serverFolder, "server.csr")
serverCert = os.path.join(serverFolder, "server.crt")
server_opensslConf = os.path.join(baseTlsLocation, "server_cert.cnf")

# Client
clientFolder = os.path.join(baseTlsLocation, "client_certs")
clientKey = os.path.join(privateFolder, "client.key")
clientCSR = os.path.join(clientFolder, "client.csr")
clientCert = os.path.join(clientFolder, "client.crt")
client_opensslConf = os.path.join(baseTlsLocation, "client_cert.cnf")

# Private key password file (option)
encPasswordFile = os.path.join(privateFolder, "mypass.enc")


if __name__ == '__main__':
    #create_selfSignedCert.generate_private_key(encPasswordFile, selfKey)
    #create_selfSignedCert.generate_csr(selfKey, selfCSR, encPasswordFile, self_opensslConf)
    #create_selfSignedCert.generate_x509_cert(selfCSR, selfKey, selfCertificate, encPasswordFile)

    #create_selfSignedCert_noenc.generate_private_key(selfKeyNoEnc)
    #create_selfSignedCert_noenc.generate_csr(selfKeyNoEnc, selfCSRNoEnc, self_opensslConf)
    #create_selfSignedCert_noenc.generate_x509_cert(selfCSRNoEnc, selfKeyNoEnc, selfCertificateNoEnc)


    # ---CA---
    #create_ECC_CA_Cert.list_curves()
    #create_ECC_CA_Cert.generate_ecc_private_key(caKey)
    #create_ECC_CA_Cert.generate_ecc_ca_cert(ca_opensslConf, caKey, caCertificate)
    # ---Server---
    #create_ECC_CA_Cert.generate_ecc_private_key(serverKey)
    #create_ECC_CA_Cert.generate_csr(serverKey, serverCSR, server_opensslConf)
    #create_ECC_CA_Cert.generate_cert(caKey, caCertificate, serverCSR, serverCert, server_opensslConf, indexFile)
    # ---Client---
    #create_ECC_CA_Cert.generate_ecc_private_key(clientKey)
    #create_ECC_CA_Cert.generate_csr(clientKey, clientCSR, client_opensslConf)
    #create_ECC_CA_Cert.generate_cert(caKey, caCertificate, clientCSR, clientCert, client_opensslConf, indexFile)
    create_ECC_CA_Cert.list_files(projectLocation)