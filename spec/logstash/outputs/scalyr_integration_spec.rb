# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/scalyr"
require "logstash/codecs/plain"
require "logstash/event"
require "json"

describe LogStash::Outputs::Scalyr do

  describe "#ssl_tests" do
      context "with default SSL configuration" do
        it "throws a ServerError due to fake api key" do
            expect {
              plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234'})
              plugin.register
              plugin.multi_receive(sample_events)
            }.to raise_error(Scalyr::Common::Client::ServerError, "error/client/badParam")
        end
      end

      context "when pointing at a location without any valid certs and not using builtin" do
        it "throws an SSLError" do
            expect {
              plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234', 'ssl_ca_bundle_path' => '/fakepath/nocerts', 'append_builtin_cert' => false})
              plugin.register
              plugin.multi_receive(sample_events)
            }.to raise_error(Scalyr::Common::Client::ClientError, "Unexpected error: java.security.InvalidAlgorithmParameterException: the trustAnchors parameter must be non-empty")
        end
      end

      context "when system certs are missing and not using builtin" do
        it "throws an SSLError" do
          `sudo mv #{OpenSSL::X509::DEFAULT_CERT_FILE} /tmp/system_cert.pem`
          `sudo mv #{OpenSSL::X509::DEFAULT_CERT_DIR} /tmp/system_certs`

          begin
            expect {
              plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234', 'append_builtin_cert' => false})
              plugin.register
              plugin.multi_receive(sample_events)
            }.to raise_error(Scalyr::Common::Client::ClientError, "Unexpected error: java.security.InvalidAlgorithmParameterException: the trustAnchors parameter must be non-empty")
          end
          ensure
            `sudo mv /tmp/system_certs #{OpenSSL::X509::DEFAULT_CERT_DIR}`
            `sudo mv /tmp/system_cert.pem #{OpenSSL::X509::DEFAULT_CERT_FILE}`
        end
      end

      context "when server hostname doesn't match the cert" do
        it "throws an SSLError" do
          agent_scalyr_com_ip = `dig +short agent.scalyr.com 2> /dev/null | tail -n 1 | tr -d "\n"`
          if agent_scalyr_com_ip.empty?
            agent_scalyr_com_ip = `getent hosts agent.scalyr.com \
            | awk '{ print $1 }' | tail -n 1 | tr -d "\n"`
          end
          mock_host = "invalid.mitm.should.fail.test.agent.scalyr.com"
          etc_hosts_entry = "#{agent_scalyr_com_ip} #{mock_host}"
          hosts_bkp = `sudo cat /etc/hosts`
          hosts_bkp = hosts_bkp.chomp
          # Add mock /etc/hosts entry and config scalyr_server entry
          `echo "#{etc_hosts_entry}" | sudo tee -a /etc/hosts`

          begin
            expect {
              plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234', 'scalyr_server' => 'https://invalid.mitm.should.fail.test.agent.scalyr.com:443'})
              plugin.register
              plugin.multi_receive(sample_events)
            }.to raise_error(Scalyr::Common::Client::ClientError, "Host name 'invalid.mitm.should.fail.test.agent.scalyr.com' does not match the certificate subject provided by the peer (CN=*.scalyr.com)")
          ensure
            # Clean up the hosts file
            `sudo truncate -s 0 /etc/hosts`
            `echo "#{hosts_bkp}" | sudo tee -a /etc/hosts`
          end
        end
      end
  end
end
