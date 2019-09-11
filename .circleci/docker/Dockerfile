FROM docker.elastic.co/logstash/logstash:7.2.0
COPY config /usr/share/logstash/config
COPY pipeline /usr/share/logstash/pipeline
COPY logstash-output-scalyr-1.0.0.pre.alpha.gem /tmp
RUN /usr/share/logstash/bin/logstash-plugin install /tmp/logstash-output-scalyr-1.0.0.pre.alpha.gem
