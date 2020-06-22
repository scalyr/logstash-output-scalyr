FROM docker.elastic.co/logstash/logstash:7.2.0
RUN /usr/share/logstash/bin/logstash-plugin install logstash-output-scalyr

COPY logstash.conf /etc/logstash/conf.d/
COPY pipelines.yml /usr/share/logstash/config/
COPY logstash.yml /usr/share/logstash/config/

EXPOSE 5044

ENTRYPOINT ["bin/logstash"]
