import os
import time
import create_selfCert
import create_selfSignedCert_noenc
import create_ECC_Cert
import create_hostCert

import source_Project
#import revoke_Cert
from configparser import ConfigParser
import subprocess

from helper import logger

cfg = ConfigParser()
cfg.read('config.ini')

TODO: 'Encrypt log file possibly. Private keys are password protected with encrypted password file though. ' \
      'Only relevant for non password protected key option!'

# Working area
projectLocation = os.getcwd()


def main():
    source_project()
    create_self_signed_certificate()
    create_ecc_certificate()
    create_server_certificate()
    create_client_certificate()


#loop through section will be preferred!
def source_project():
    # Create the project area
    source_Project.create_folder(cfg.get('installation', 'certsFolder'))
    source_Project.create_folder(cfg.get('installation', 'privateFolder'))
    source_Project.create_folder(cfg.get('installation', 'newCertsFolder'))
    source_Project.create_folder(cfg.get('installation', 'caCrlFolder'))
    source_Project.create_file(cfg.get('installation', 'indexFile'))
    source_Project.create_file(cfg.get('installation', 'serialFile'))
    source_Project.create_file(cfg.get('installation', 'crlnumberFile'))

    # find suitable openssl.cnf dependent on system/linux flavour and make hi-level changes to CA defaults
    source_Project.get_source(cfg.get('misc', 'sourceOpenSSLConf'),
                              cfg.get('ca', 'opensslConf'))
    source_Project.edit_openssl(cfg.get('ca', 'opensslConf'),
                                'dir',
                                cfg.get('installation', 'baseTlsLocation'))
    source_Project.edit_openssl(cfg.get('ca', 'opensslConf'),
                                'certificate',
                                cfg.get('ca', 'caCertificate'))
    source_Project.edit_openssl(cfg.get('ca', 'opensslConf'),
                                'private_key',
                                cfg.get('ca', 'caKey'))


def create_self_signed_certificate():
    # ---Self-Signed RSA with X509 cert---
    source_Project.get_source(projectLocation + "/tls/self_openssl.cnf",
                              cfg.get('self', 'self_opensslConf'))
    source_Project.edit_openssl(cfg.get('self', 'self_opensslConf'), "", "")

    create_selfCert.generate_rsa_key(cfg.get('self', 'selfKey'),
                                           cfg.get('misc', 'encPasswordFile'))

    create_selfCert.generate_csr(cfg.get('self', 'selfkey'),
                                       cfg.get('self', 'selfCSR'),
                                       cfg.get('self', 'self_opensslConf'),
                                       cfg.get('misc', 'encPasswordFile'))

    create_selfCert.generate_x509_cert(cfg.get('self', 'selfCSR'),
                                             cfg.get('self', 'selfkey'),
                                             cfg.get('self', 'selfCertificate'),
                                             cfg.get('misc', 'encPasswordFile'))


def create_ecc_certificate():
    # ---ECC CA---
    source_Project.get_source(projectLocation + "/tls/self_openssl.cnf",
                              cfg.get('self', 'self_opensslConf'))
    source_Project.edit_openssl(cfg.get('self', 'self_opensslConf'), "", "")
    # create_ECC_CA_Cert.list_curves()
    create_ECC_Cert.generate_ecc_key(cfg.get('ca', 'caKey'))
    create_ECC_Cert.generate_ecc_cert(cfg.get('self', 'self_opensslConf'),
                                         cfg.get('ca', 'caKey'),
                                         cfg.get('ca', 'caCertificate'))


def create_server_certificate():
    # ---Server---
    source_Project.get_source(projectLocation + "/tls/server_openssl.cnf",
                              cfg.get('server', 'server_opensslConf'))
    source_Project.edit_openssl(cfg.get('server', 'server_opensslConf'), "", "")

    create_ECC_Cert.generate_ecc_key(cfg.get('server', 'serverKey'))
    create_hostCert.generate_csr(cfg.get('server', 'serverKey'),
                                   cfg.get('server', 'serverCSR'),
                                   cfg.get('server', 'server_opensslConf'))
    create_hostCert.generate_cert(cfg.get('ca', 'caKey'),
                                    cfg.get('ca', 'caCertificate'),
                                    cfg.get('server', 'serverCSR'),
                                    cfg.get('server', 'serverCert'),
                                    cfg.get('ca', 'opensslConf'))


def create_client_certificate():
    # ---Client---
    source_Project.get_source(projectLocation + "/tls/client_openssl.cnf",
                              cfg.get('client', 'client_opensslConf'))
    source_Project.edit_openssl(cfg.get('client', 'client_opensslConf'), "", "")

    create_ECC_Cert.generate_ecc_key(cfg.get('client', 'clientKey'))
    create_hostCert.generate_csr(cfg.get('client', 'clientKey'),
                                   cfg.get('client', 'clientCSR'),
                                   cfg.get('client', 'client_opensslConf'))
    create_hostCert.generate_cert(cfg.get('ca', 'caKey'),
                                    cfg.get('ca', 'caCertificate'),
                                    cfg.get('client', 'clientCSR'),
                                    cfg.get('client', 'clientCert'),
                                    cfg.get('ca', 'opensslConf'))


if __name__ == '__main__':
    main()



    ##############################
    # --- Now do some work --- :-)
    ##############################


    '''
    # --- Self-Signed with no passphrase on private key---
    create_selfSignedCert_noenc.generate_rsa_key(cfg.get('installation', 'selfKeyNoEnc'))
    create_selfSignedCert_noenc.generate_csr(cfg.get('installation', 'selfKeyNoEnc'),
                                             cfg.get('installation', 'selfCSRNoEnc'),
                                             cfg.get('installation', 'self_opensslConf'))
    create_selfSignedCert_noenc.generate_x509_cert(cfg.get('installation', 'selfCSRNoEnc'),
                                                   cfg.get('installation', 'selfKeyNoEnc'),
                                                   cfg.get('installation', 'selfCertificateNoEnc'))
    '''







    #revoke_Cert.revoke_cert(server_opensslConf, serverCert, indexFile)
    #revoke_Cert.generate_revocation_list(server_opensslConf, caCrlFile)

    # create_ECC_CA_Cert.list_files(projectLocation)