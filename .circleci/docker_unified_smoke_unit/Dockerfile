#--------------------------------------------------------------------------------------------------
# This dockerfile builds the unified image for running Scalyr agent unit & smoke tests
#
# It requires the following files:
#
# smoketest
#   override_files
#     agent.json (agent config file with placeholder serverHost token)
#   smoketest.py (main smoketest python script)
# unittest
#   unittest.sh (unittest script)
#--------------------------------------------------------------------------------------------------

FROM centos

RUN yum install -y sudo gcc gcc-c++ make git patch openssl-devel zlib-devel readline-devel sqlite-devel bzip2-devel which wget
RUN yum install -y libffi-devel
RUN yum install -y ruby-devel gcc make rpm-build rubygems  # fpm needed for building rpm
RUN yum install -y initscripts
# Install fpm globally
RUN gem install --no-user-install --no-ri --no-rdoc fpm
RUN yum -y install net-tools
RUN yum install -y epel-release && yum install -y python36
RUN python3.6 -m pip install requests

RUN useradd -ms /bin/bash scalyr \
&& echo "scalyr:scalyr" | chpasswd \
&& usermod -aG wheel scalyr \
&& echo "scalyr ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# RUN gem install --no-ri --no-rdoc fpm

USER scalyr
WORKDIR /home/scalyr

COPY unittest smoketest /tmp/
