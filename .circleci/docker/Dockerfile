FROM docker.elastic.co/logstash/logstash:7.2.0

# libzstd is needed for zstandard support
USER root
RUN yum -y install epel-release && yum makecache && yum -y install zstd libzstd
USER logstash

COPY config /usr/share/logstash/config
COPY pipeline /usr/share/logstash/pipeline

ENV GEM_HOME=/opt/logstash/vendor/bundle/jruby/2.5.0
RUN /usr/share/logstash/bin/ruby /opt/logstash/vendor/jruby/bin/gem install zstandard
RUN echo 'gem "zstandard"' >> /opt/logstash/Gemfile

COPY logstash-output-scalyr.gem /tmp
RUN /usr/share/logstash/bin/logstash-plugin install /tmp/logstash-output-scalyr.gem

# Needed to set this environment variable for zstandard gem to work (by default it looks for
# libzstd.so without .1 version suffix)
ENV ZSTANDARD_LIBRARY=/usr/lib64/libzstd.so.1
