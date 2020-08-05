# frozen_string_literal: true

#
# Scalyr Output Plugin for Fluentd
#
# Copyright (C) 2015 Scalyr, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/scalyr"
require "logstash/codecs/plain"
require "logstash/event"
require "json"
require "helper"
require "flexmock/test_unit"

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

  describe "#ssl_tests"
      context "test_good_ssl_certificates" do
        it "throws no errors" do
            plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234'})
            plugin.multi_receive(sample_events)
        end
      end

      context "test_no_ssl_certificates" do
        it "throws no errors" do
            plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234'})
            plugin.multi_receive(sample_events)
        end
      end

      context "test_bad_ssl_certificates" do
        it "throws some errors" do
            plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234'})
            plugin.multi_receive(sample_events)
        end
      end

      context "test_bad_system_ssl_certificates" do
        it "throws some errors" do
          `sudo mv #{OpenSSL::X509::DEFAULT_CERT_FILE} /tmp/system_cert.pem`
          `sudo mv #{OpenSSL::X509::DEFAULT_CERT_DIR} /tmp/system_certs`

          begin
            plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234'})
            plugin.multi_receive(sample_events)
          end
          ensure
            `sudo mv /tmp/system_certs #{OpenSSL::X509::DEFAULT_CERT_DIR}`
            `sudo mv /tmp/system_cert.pem #{OpenSSL::X509::DEFAULT_CERT_FILE}`
        end
      end

      context test_hostname_verification do
        it "throws some errors" it
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
            plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234'})
            plugin.multi_receive(sample_events)
          ensure
            # Clean up the hosts file
            `sudo truncate -s 0 /etc/hosts`
            `echo "#{hosts_bkp}" | sudo tee -a /etc/hosts`
          end
        end
      end
  end
end
