import os

import create_selfSignedCert
import create_selfSignedCert_noenc
import create_ECC_CA_Cert
import revoke_Cert
from configparser import ConfigParser

cfg = ConfigParser()
cfg.read('config.ini')

TODO: 'Encrypt log file possibly. Private keys are password protected with encrypted password file though. ' \
      'Only relevant for non password protected key option!'

# Working area
projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, cfg.get('installation', 'baseTlsLocation'))
opensslConf = os.path.join(baseTlsLocation, cfg.get('installation', 'opensslConf'))
privateFolder = os.path.join(baseTlsLocation,  cfg.get('installation', 'privateFolder'))
certsFolder = os.path.join(baseTlsLocation, cfg.get('installation', 'certsFolder'))
serialFile = os.path.join(baseTlsLocation, cfg.get('installation', 'serialFile'))
indexFile = os.path.join(baseTlsLocation,cfg.get('installation', 'indexFile'))
# Private key password file (option)
encPasswordFile = os.path.join(privateFolder, cfg.get('installation', 'encPasswordFile'))


# Self-Signed
selfKey = os.path.join(privateFolder, cfg.get('self-signed', 'selfkey'))
selfCertificate = os.path.join(certsFolder, cfg.get('self-signed', 'selfCertificate'))
selfCSR = os.path.join(certsFolder, cfg.get('self-signed', 'selfCSR'))
selfKeyNoEnc = os.path.join(privateFolder, cfg.get('self-signed', 'selfKeyNoEnc'))
selfCSRNoEnc = os.path.join(certsFolder, cfg.get('self-signed', 'selfCSRNoEnc'))
selfCertificateNoEnc = os.path.join(certsFolder, cfg.get('self-signed', 'selfCertificateNoEnc'))
self_opensslConf = os.path.join(baseTlsLocation, cfg.get('self-signed', 'self_opensslConf'))

# CA
caKey = os.path.join(privateFolder, cfg.get('ca', 'caKey'))
caCertificate = os.path.join(certsFolder, cfg.get('ca','caCertificate'))
ca_opensslConf = os.path.join(baseTlsLocation, cfg.get('ca','ca_opensslConf'))
caCrlFolder = os.path.join(baseTlsLocation, cfg.get('ca','caCrlFolder'))
caCrlFile = os.path.join(caCrlFolder, cfg.get('ca', 'caCrlFile'))

# Server
serverFolder = os.path.join(baseTlsLocation, cfg.get('server', 'serverFolder'))
serverKey = os.path.join(privateFolder, cfg.get('server', 'serverKey'))
serverCSR = os.path.join(serverFolder, cfg.get('server', 'serverCSR'))
serverCert = os.path.join(serverFolder, cfg.get('server', 'serverCert'))
server_opensslConf = os.path.join(baseTlsLocation, cfg.get('server', 'server_opensslConf'))

# Client
clientFolder = os.path.join(baseTlsLocation, cfg.get('client', 'clientFolder'))
clientKey = os.path.join(privateFolder, cfg.get('client', 'clientKey'))
clientCSR = os.path.join(clientFolder, cfg.get('client', 'clientCSR'))
clientCert = os.path.join(clientFolder, cfg.get('client', 'clientCert'))
client_opensslConf = os.path.join(baseTlsLocation, cfg.get('client', 'client_opensslConf'))


if __name__ == '__main__':
    create_selfSignedCert.generate_private_key(encPasswordFile, selfKey)
    create_selfSignedCert.generate_csr(selfKey, selfCSR, encPasswordFile, self_opensslConf)
    create_selfSignedCert.generate_x509_cert(selfCSR, selfKey, selfCertificate, encPasswordFile)

    create_selfSignedCert_noenc.generate_private_key(selfKeyNoEnc)
    create_selfSignedCert_noenc.generate_csr(selfKeyNoEnc, selfCSRNoEnc, self_opensslConf)
    create_selfSignedCert_noenc.generate_x509_cert(selfCSRNoEnc, selfKeyNoEnc, selfCertificateNoEnc)


    # ---CA---
    create_ECC_CA_Cert.list_curves()
    create_ECC_CA_Cert.generate_ecc_private_key(caKey)
    create_ECC_CA_Cert.generate_ecc_ca_cert(ca_opensslConf, caKey, caCertificate)
    # ---Server---
    create_ECC_CA_Cert.generate_ecc_private_key(serverKey)
    create_ECC_CA_Cert.generate_csr(serverKey, serverCSR, server_opensslConf)
    create_ECC_CA_Cert.generate_cert(caKey, caCertificate, serverCSR, serverCert, server_opensslConf, indexFile)
    # ---Client---
    create_ECC_CA_Cert.generate_ecc_private_key(clientKey)
    create_ECC_CA_Cert.generate_csr(clientKey, clientCSR, client_opensslConf)
    create_ECC_CA_Cert.generate_cert(caKey, caCertificate, clientCSR, clientCert, client_opensslConf, indexFile)
    create_ECC_CA_Cert.list_files(projectLocation)

    revoke_Cert.revoke_cert(server_opensslConf, serverCert, indexFile)
    revoke_Cert.generate_revocation_list(server_opensslConf, caCrlFile)
