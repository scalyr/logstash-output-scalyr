FROM ubuntu:18.04

RUN apt-get update
RUN apt-get install -y jruby
RUN apt-get install -y gnupg
RUN apt-get install -y wget
RUN wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
RUN apt-get install -y apt-transport-https
RUN echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list
RUN apt-get update && apt-get install -y logstash
WORKDIR /usr/share/logstash/
RUN bin/logstash-plugin install logstash-output-scalyr
COPY logstash.conf /etc/logstash/conf.d
COPY pipelines.yml /usr/share/logstash/config/

EXPOSE 5044

ENTRYPOINT ["bin/logstash"]