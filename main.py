import os
import time
from configparser import ConfigParser
import create_selfCert
import create_selfCert_noenc
import create_ECC_Cert
import create_hostCert
import create_rootCACert
import source_Project
import revoke_Cert
import renew_Cert

cfg = ConfigParser()
cfg.read('config.ini')

TODO: 'Encrypt log file possibly. Private keys are password protected with encrypted password file though. ' \
      'Only relevant for non password protected key option!'

# Working area
projectLocation = os.getcwd()

def main():
    source_project()
    #create_self_signed_certificate()
    #create_self_signed_certificate_noenc()
    #create_ecc_certificate()
    #create_server_certificate()
    #create_client_certificate()
    #create_root_ca_and_sign_certs()
    #revoke_certificate()
    #renew_certificate()

    # WIP for next stage v1 onwards
    #create_key.generate_key(cfg.get('commands', 'cmdPrivKeyRSA'))
    #create_key.generate_key(cfg.get('commands', 'cmdPrivKeyRSAnoenc'))
    #create_key.generate_key(cfg.get('commands', 'cmdPrivKeyECC'))

    #create_ECC_Cert.list_files(cfg.get('default', 'baseTlsLocation'))


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
    source_Project.get_source(cfg.get('runtime', 'sourceOpenSSLConf'),
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


# These are all procedural walk-throughs of a very similar nature
def create_self_signed_certificate():
    # ---Self-Signed RSA with X509 cert---
    source_Project.get_source(projectLocation + "/tls/self_openssl.cnf",
                              cfg.get('self', 'self_opensslConf'))
    source_Project.edit_openssl(cfg.get('self', 'self_opensslConf'), "", "")

    create_selfCert.generate_rsa_key(cfg.get('self', 'selfKey'),
                                     cfg.get('runtime', 'encPasswordFile'))

    create_selfCert.generate_csr(cfg.get('self', 'selfkey'),
                                       cfg.get('self', 'selfCSR'),
                                       cfg.get('self', 'self_opensslConf'),
                                       cfg.get('runtime', 'encPasswordFile'))

    create_selfCert.generate_x509_cert(cfg.get('self', 'selfCSR'),
                                             cfg.get('self', 'selfkey'),
                                             cfg.get('self', 'selfCertificate'),
                                             cfg.get('runtime', 'encPasswordFile'))


def create_self_signed_certificate_noenc():
    # ---Self-Signed RSA with X509 cert---
    source_Project.get_source(projectLocation + "/tls/self_openssl.cnf",
                              cfg.get('self', 'self_opensslConf'))
    source_Project.edit_openssl(cfg.get('self', 'self_opensslConf'), "", "")

    create_selfCert_noenc.generate_rsa_key(cfg.get('self', 'selfKeyNoEnc'))
    create_selfCert_noenc.generate_csr(cfg.get('self', 'selfkeyNoEnc'),
                                       cfg.get('self', 'selfCSRNoEnc'),
                                       cfg.get('self', 'self_opensslConf'))
    create_selfCert_noenc.generate_x509_cert(cfg.get('self', 'selfCSRNoEnc'),
                                             cfg.get('self', 'selfkeyNoEnc'),
                                             cfg.get('self', 'selfCertificateNoEnc'))


def create_ecc_certificate():
    # ---ECC CA---
    source_Project.get_source(projectLocation + "/tls/self_openssl.cnf",
                              cfg.get('self', 'self_opensslConf'))
    source_Project.edit_openssl(cfg.get('self', 'self_opensslConf'), "", "")
    # create_ECC_Cert.list_curves()
    create_ECC_Cert.generate_ecc_key(cfg.get('ca', 'caKey'))
    create_ECC_Cert.generate_ecc_cert(cfg.get('self', 'self_opensslConf'),
                                         cfg.get('ca', 'caKey'),
                                         cfg.get('ca', 'caCertificate'))


def create_server_certificate():
    # ---Server---
    source_Project.get_source(projectLocation + "/tls/server_openssl.cnf",
                              cfg.get('server', 'server_opensslConf'))
    source_Project.edit_openssl(cfg.get('server', 'server_opensslConf'),
                                "commonName",
                                cfg.get('server', 'serverCommonName'))

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
    source_Project.edit_openssl(cfg.get('client', 'client_opensslConf'),
                                "commonName",
                                cfg.get('client', 'clientCommonName'))

    create_ECC_Cert.generate_ecc_key(cfg.get('client', 'clientKey'))
    create_hostCert.generate_csr(cfg.get('client', 'clientKey'),
                                 cfg.get('client', 'clientCSR'),
                                 cfg.get('client', 'client_opensslConf'))
    create_hostCert.generate_cert(cfg.get('ca', 'caKey'),
                                  cfg.get('ca', 'caCertificate'),
                                  cfg.get('client', 'clientCSR'),
                                  cfg.get('client', 'clientCert'),
                                  cfg.get('ca', 'opensslConf'))


def create_root_ca_and_sign_certs():
    # ---Self-Signed RSA with X509 cert---
    source_Project.edit_openssl(cfg.get('ca', 'opensslConf'),
                                'certificate',
                                cfg.get('root', 'rootCert'))
    source_Project.edit_openssl(cfg.get('ca', 'opensslConf'),
                                'private_key',
                                cfg.get('root', 'rootKey'))

    create_rootCACert.create_ca_key(cfg.get('runtime', 'encPasswordFile'),
                                    cfg.get('root', 'rootKey'))
    create_rootCACert.create_ca_cert(cfg.get('root', 'rootKey'),
                                     cfg.get('root', 'rootCert'),
                                     cfg.get('runtime', 'encPasswordFile'),
                                     cfg.get('self', 'self_opensslConf'))
    create_rootCACert.sign_server_cert(cfg.get('server', 'serverCSR'),
                                       cfg.get('root', 'rootCert'),
                                       cfg.get('root', 'rootKey'),
                                       cfg.get('server', 'serverCert'),
                                       cfg.get('runtime', 'encPasswordFile'))


def revoke_certificate():
    revoke_Cert.revoke_cert(cfg.get('ca', 'opensslConf'),
                            cfg.get('server', 'serverCert'))
    revoke_Cert.create_revocation_list(cfg.get('ca', 'opensslConf'),
                                       cfg.get('root', 'caCrlFile'))


def renew_certificate():
    renew_Cert.export_old_csr(cfg.get('root', 'rootCert'),
                              cfg.get('root', 'rootKey'),
                              cfg.get('root', 'rootCSR'))
    renew_Cert.renew_cert(cfg.get('root', 'rootCSR'),
                          cfg.get('root', 'rootKey'),
                          cfg.get('root', 'rootNewCert'))


if __name__ == '__main__':
    main()



