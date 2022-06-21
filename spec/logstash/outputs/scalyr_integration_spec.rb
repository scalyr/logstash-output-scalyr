# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/scalyr"
require "logstash/codecs/plain"
require "logstash/event"
require "json"
require 'webmock/rspec'

# Require the specific version of `json` used in logstash
gem 'json', '1.8.6'
require 'json'

WebMock.allow_net_connect!

RSpec.configure do |rspec|
  rspec.expect_with :rspec do |c|
    c.max_formatted_output_length = nil
  end
end

describe LogStash::Outputs::Scalyr do
  let(:sample_events) {
    events = []
    for i in 1..3 do
      e = LogStash::Event.new
      e.set('source_host', "my host #{i}")
      e.set('source_file', "my file #{i}")
      e.set('seq', i)
      e.set('nested', {'a'=>1, 'b'=>[3,4,5]})
      e.set('tags', ['t1', 't2', 't3'])
      events.push(e)
    end
    events
  }

  describe "#ssl_tests" do
      context "with default SSL configuration" do
        it "throws a ServerError due to fake api key" do
              plugin = LogStash::Outputs::Scalyr.new({
                'api_write_token' => '1234',
                'perform_connectivity_check' => false,
                'max_retries' => 2,
                'retry_max_interval' => 2,
                'retry_initial_interval' => 0.2,
              })
              plugin.register
              plugin.instance_variable_set(:@running, false)
              allow(plugin.instance_variable_get(:@logger)).to receive(:warn)
              plugin.multi_receive(sample_events)
              expect(plugin.instance_variable_get(:@logger)).to have_received(:warn).with("Error uploading to Scalyr (will backoff-retry)",
                {
                  :error_class=>"Scalyr::Common::Client::ServerError",
                  :batch_num=>1,
                  :code=>401,
                  :message=>"error/client/badParam",
                  :payload_size=>737,
                  :record_count=>3,
                  :total_batches=>1,
                  :url=>"https://agent.scalyr.com/addEvents",
                  :will_retry_in_seconds=>0.4,
                  :body=>"{\n  \"message\": \"Couldn't decode API token ...234.\",\n  \"status\": \"error/client/badParam\"\n}"
                }
              )
        end
      end

      context "when pointing at a location without any valid certs and not using builtin" do
        it "throws an SSLError" do
              plugin = LogStash::Outputs::Scalyr.new({
                'api_write_token' => '1234',
                'perform_connectivity_check' => false,
                'ssl_ca_bundle_path' => '/fakepath/nocerts',
                'append_builtin_cert' => false,
                'max_retries' => 2,
                'retry_max_interval' => 2,
                'retry_initial_interval' => 0.2,
              })
              plugin.register
              plugin.instance_variable_set(:@running, false)
              allow(plugin.instance_variable_get(:@logger)).to receive(:warn)
              plugin.multi_receive(sample_events)
              expect(plugin.instance_variable_get(:@logger)).to have_received(:warn).with("Error uploading to Scalyr (will backoff-retry)",
                {
                  :error_class=>"Manticore::UnknownException",
                  :batch_num=>1,
                  :message=>"java.lang.RuntimeException: Unexpected error: java.security.InvalidAlgorithmParameterException: the trustAnchors parameter must be non-empty",
                  :payload_size=>737,
                  :record_count=>3,
                  :total_batches=>1,
                  :url=>"https://agent.scalyr.com/addEvents",
                  :will_retry_in_seconds=>0.4
                }
              )
        end
      end

      context "when system certs are missing and not using builtin" do
        it "throws an SSLError" do
          `sudo mv #{OpenSSL::X509::DEFAULT_CERT_FILE} /tmp/system_cert.pem`
          `sudo mv #{OpenSSL::X509::DEFAULT_CERT_DIR} /tmp/system_certs`

          begin
              plugin = LogStash::Outputs::Scalyr.new({
                'api_write_token' => '1234',
                'perform_connectivity_check' => false,
                'append_builtin_cert' => false,
                'max_retries' => 2,
                'retry_max_interval' => 2,
                'retry_initial_interval' => 0.2,
              })
              plugin.register
              plugin.instance_variable_set(:@running, false)
              allow(plugin.instance_variable_get(:@logger)).to receive(:warn)
              plugin.multi_receive(sample_events)
              expect(plugin.instance_variable_get(:@logger)).to have_received(:warn).with("Error uploading to Scalyr (will backoff-retry)",
                {
                  :error_class=>"Manticore::UnknownException",
                  :batch_num=>1,
                  :message=>"java.lang.RuntimeException: Unexpected error: java.security.InvalidAlgorithmParameterException: the trustAnchors parameter must be non-empty",
                  :payload_size=>737,
                  :record_count=>3,
                  :total_batches=>1,
                  :url=>"https://agent.scalyr.com/addEvents",
                  :will_retry_in_seconds=>0.4
                }
              )
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
              plugin = LogStash::Outputs::Scalyr.new({
                'api_write_token' => '1234',
                'perform_connectivity_check' => false,
                'scalyr_server' => 'https://invalid.mitm.should.fail.test.agent.scalyr.com:443',
                'max_retries' => 2,
                'retry_max_interval' => 2,
                'retry_initial_interval' => 0.2,
              })
              plugin.register
              plugin.instance_variable_set(:@running, false)
              allow(plugin.instance_variable_get(:@logger)).to receive(:warn)
              plugin.multi_receive(sample_events)
              expect(plugin.instance_variable_get(:@logger)).to have_received(:warn).with("Error uploading to Scalyr (will backoff-retry)",
                {
                  :error_class=>"Manticore::UnknownException",
                  :batch_num=>1,
                  :message=>"Certificate for <invalid.mitm.should.fail.test.agent.scalyr.com> doesn't match any of the subject alternative names: [*.scalyr.com, scalyr.com]",
                  :payload_size=>737,
                  :record_count=>3,
                  :total_batches=>1,
                  :url=>"https://invalid.mitm.should.fail.test.agent.scalyr.com/addEvents",
                  :will_retry_in_seconds=>0.4
                }
              )
          ensure
            # Clean up the hosts file
            `sudo truncate -s 0 /etc/hosts`
            `echo "#{hosts_bkp}" | sudo tee -a /etc/hosts`
          end
        end
      end

      context "when an error occurs with retries at 15" do
        it "exits after 5 retries and emits a log" do
              plugin = LogStash::Outputs::Scalyr.new({
                'api_write_token' => '1234',
                'perform_connectivity_check' => false,
                'ssl_ca_bundle_path' => '/fakepath/nocerts',
                'append_builtin_cert' => false,
                'max_retries' => 15,
                'retry_max_interval' => 0.5,
                'retry_initial_interval' => 0.2,
              })
              plugin.register
              allow(plugin.instance_variable_get(:@logger)).to receive(:error)
              plugin.multi_receive(sample_events)
              expect(plugin.instance_variable_get(:@logger)).to have_received(:error).with("Failed to send 3 events after 15 tries.", anything
              )
        end
      end
  end

  describe "response_handling_tests" do
    context "when receiving a 503 response" do
      it "don't throw an error but do log one to debug" do
        stub_request(:post, "https://agent.scalyr.com/addEvents").
          to_return(status: 503, body: "stubbed response", headers: {})

        plugin = LogStash::Outputs::Scalyr.new({
          'api_write_token' => '1234',
          'perform_connectivity_check' => false,
          'ssl_ca_bundle_path' => '/fakepath/nocerts',
          'append_builtin_cert' => false,
          'max_retries' => 2,
          'retry_max_interval' => 2,
          'retry_initial_interval' => 0.2,
        })
        plugin.register
        plugin.instance_variable_set(:@running, false)

        allow(plugin.instance_variable_get(:@logger)).to receive(:debug)
        plugin.multi_receive(sample_events)
        expect(plugin.instance_variable_get(:@logger)).to have_received(:debug).with("Error uploading to Scalyr (will backoff-retry)",
          {
            :error_class=>"Scalyr::Common::Client::ServerError",
            :batch_num=>1,
            :code=>503,
            :message=>"Invalid JSON response from server",
            :payload_size=>737,
            :record_count=>3,
            :total_batches=>1,
            :url=>"https://agent.scalyr.com/addEvents",
            :will_retry_in_seconds=>0.4,
            :body=>"stubbed response"
          }
        )
      end
    end

    context "when receiving a 500 response" do
      it "don't throw an error but do log one to error" do
        stub_request(:post, "https://agent.scalyr.com/addEvents").
          to_return(status: 500, body: "stubbed response", headers: {})

        plugin = LogStash::Outputs::Scalyr.new({
          'api_write_token' => '1234',
          'perform_connectivity_check' => false,
          'ssl_ca_bundle_path' => '/fakepath/nocerts',
          'append_builtin_cert' => false,
          'max_retries' => 2,
          'retry_max_interval' => 2,
          'retry_initial_interval' => 0.2,
        })
        plugin.register
        plugin.instance_variable_set(:@running, false)

        allow(plugin.instance_variable_get(:@logger)).to receive(:warn)
        plugin.multi_receive(sample_events)
        expect(plugin.instance_variable_get(:@logger)).to have_received(:warn).with("Error uploading to Scalyr (will backoff-retry)",
          {
            :error_class=>"Scalyr::Common::Client::ServerError",
            :batch_num=>1,
            :code=>500,
            :message=>"Invalid JSON response from server",
            :payload_size=>737,
            :record_count=>3,
            :total_batches=>1,
            :url=>"https://agent.scalyr.com/addEvents",
            :will_retry_in_seconds=>0.4,
            :body=>"stubbed response"
          }
        )
      end
    end

    context "when receiving a long non-json response" do
      it "don't throw an error but do log one to error" do
        stub_request(:post, "https://agent.scalyr.com/addEvents").
          to_return(status: 500, body: "0123456789" * 52, headers: {})

        plugin = LogStash::Outputs::Scalyr.new({
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'ssl_ca_bundle_path' => '/fakepath/nocerts',
            'append_builtin_cert' => false,
            'max_retries' => 2,
            'retry_max_interval' => 2,
            'retry_initial_interval' => 0.2,
        })
        plugin.register
        plugin.instance_variable_set(:@running, false)

        allow(plugin.instance_variable_get(:@logger)).to receive(:warn)
        plugin.multi_receive(sample_events)
        expect(plugin.instance_variable_get(:@logger)).to have_received(:warn).with("Error uploading to Scalyr (will backoff-retry)",
          {
            :error_class=>"Scalyr::Common::Client::ServerError",
            :batch_num=>1,
            :code=>500,
            :message=>"Invalid JSON response from server",
            :payload_size=>737,
            :record_count=>3,
            :total_batches=>1,
            :url=>"https://agent.scalyr.com/addEvents",
            :will_retry_in_seconds=>0.4,
            :body=>("0123456789" * 50) + "012345678..."
          }
        )
      end
    end

    context 'when DLQ is enabled' do
      let(:dlq_writer) { double('DLQ writer') }
      it 'should send the event to the DLQ' do
        stub_request(:post, "https://agent.scalyr.com/addEvents").
          to_return(status: 500, body: "stubbed response", headers: {})

        plugin = LogStash::Outputs::Scalyr.new({
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'ssl_ca_bundle_path' => '/fakepath/nocerts',
            'append_builtin_cert' => false,
            'max_retries' => 2,
            'retry_max_interval' => 2,
            'retry_initial_interval' => 0.2,
        })
        plugin.register
        plugin.instance_variable_set(:@running, false)
        plugin.instance_variable_set('@dlq_writer', dlq_writer)

        expect(dlq_writer).to receive(:write).exactly(3).times.with(anything, anything)
        plugin.multi_receive(sample_events)
      end
    end
  end

end
