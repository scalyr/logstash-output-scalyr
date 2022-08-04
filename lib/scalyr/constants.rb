# encoding: utf-8

PLUGIN_VERSION = "v0.2.7.beta"

# Special event level attribute name which can be used for setting event level serverHost attribute
EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME = '__origServerHost'

# Path to the bundled root CA certs used to sign server cert
CA_CERTS_PATH = File.expand_path(File.join(File.dirname(__FILE__), + "/certs/ca_certs.crt"))

# Additional check on import to catch this issue early (in case of a invalid path or similar)
if not File.file?(CA_CERTS_PATH)
  raise Errno::ENOENT.new("Invalid path specified for CA_CERTS_PATH module constant (likely a developer error).")
end
