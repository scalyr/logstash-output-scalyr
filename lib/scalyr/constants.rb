# encoding: utf-8

PLUGIN_VERSION = "v0.2.5.beta"

# Special event level attribute name which can be used for setting event level serverHost attribute
EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME = '__origServerHost'

# Path to the bundled server root CA cert
#  openssl x509 -in lib/scalyr/certs/ca.pem
#     Data:
#        Version: 3 (0x2)
#        Serial Number:
#            13:7d:53:9c:aa:7c:31:a9:a4:33:70:19:68:84:7a:8d
#    Signature Algorithm: sha384WithRSAEncryption
#        Issuer: C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust RSA Certification Authority
CA_CERT_PATH = File.expand_path(File.join(File.dirname(__FILE__), + "/certs/ca_certs.crt"))

# Cert which is append to a copy of "/etc/ssl/certs/ca-bundle.crt" file.
# This is done for backward compatibility and convenience reasons when "appending_builtin_cert"
# plugin config option is set to true - eventually we want to default it to false and just rely
# on system ca bundle by default.
CA_CERT_STRING = File.read(CA_CERT_PATH)
