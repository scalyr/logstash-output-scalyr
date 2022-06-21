#----------------------------------------------------------------------------------------
# Runs agent smoketest for docker:
#    - Assumes that the current scalyr-agent-2 root directory contains the test branch and that
#       the VERSION file can be overwritten (ie. the scalyr-agent-2 directory is a "throwaway" copy.
#    - Launch agent docker image
#    - Launch uploader docker image (writes lines to stdout)
#    - Launch verifier docker image (polls for liveness of agent and
#       uploader, as well as verifies expected uploaded lines)
#
# Expects the following env vars:
#   SCALYR_API_KEY
#   SCALYR_SERVER
#   READ_API_KEY (Read api key. 'SCALYR_' prefix intentionally omitted to suppress in status -v)
#   CIRCLE_BUILD_NUM
#
# Expects following positional args:
#   $1 : smoketest image tag
#   $2 : max secs until test hard fails
#   $3 : plugin gemfile
#   $4 : logstash docker context (containing Dockerfile for building logstash image & also config directories)
#
# e.g. usage
#   smoketest_docker.sh scalyr/scalyr-agent-ci-smoketest:10 300 $gemfile .circleci/docker
#----------------------------------------------------------------------------------------

# The following variables are needed
# Docker image in which runs smoketest python3 code
smoketest_image=$1

# Max seconds before the test hard fails
max_wait=$2

gemfile=$3

# Docker context directory that is expected to contain the following:
# 1. locally mounted directories
# 2. Dockerfile for building logstash image
# 3. gemfile of scalyr logstash plugin
logstash_docker_context=$4

# How many workers to configure for this test, to allow testing single and multi threaded
worker_count=$5

# We don't have an easy way to update base test docker images which come bundled
# with the smoketest.py file
# (.circleci/docker_unified_smoke_unit/smoketest/smoketest.py ->
# /tmp/smoketest.py) so we simply download this file from the github before running the tests.
# That's not great, but it works.
SMOKE_TESTS_SCRIPT_BRANCH=${CIRCLE_BRANCH:-"master"}
SMOKE_TESTS_SCRIPT_REPO=${CIRCLE_PROJECT_REPONAME:-"logstash-output-scalyr"}

SMOKE_TESTS_SCRIPT_URL="https://raw.githubusercontent.com/scalyr/${SMOKE_TESTS_SCRIPT_REPO}/${SMOKE_TESTS_SCRIPT_BRANCH}/.circleci/docker_unified_smoke_unit/smoketest/smoketest.py"
DOWNLOAD_SMOKE_TESTS_SCRIPT_COMMAND="sudo curl -o /tmp/smoketest.py ${SMOKE_TESTS_SCRIPT_URL}"

COMPRESSION_TYPE=${COMPRESSION_TYPE:-"deflate"}

#----------------------------------------------------------------------------------------
# Everything below this script should be fully controlled by above variables
#----------------------------------------------------------------------------------------

# Smoketest code (built into smoketest image)
# smoketest.py must run as root otherwise Uploader doesn't have permissions to write to shared mount /app/xxxx.log
smoketest_script="sudo -E python3 /tmp/smoketest.py"

# container names for all test containers
# The suffixes MUST be one of (agent, uploader, verifier) to match verify_upload::DOCKER_CONTNAME_SUFFIXES
contname_agent="ci-plugin-logstash-${CIRCLE_BUILD_NUM}-agent"
contname_uploader="ci-plugin-logstash-${CIRCLE_BUILD_NUM}-uploader"
contname_verifier="ci-plugin-logstash-${CIRCLE_BUILD_NUM}-verifier"


# Kill leftover containers
function kill_and_delete_docker_test_containers() {
    echo ""
    for cont in $contname_agent $contname_uploader $contname_verifier
    do
        if [[ -n `docker ps | grep $cont` ]]; then
            docker kill $cont
        fi
        if [[ -n `docker ps -a | grep $cont` ]]; then
            docker rm $cont;
        fi
    done
    echo ""
}
kill_and_delete_docker_test_containers
echo `pwd`


#------------------------------------------------------------------------------------------------------------
# Create the shared file(s) that the uploader containers will write to and the logstash "agent" will read from
# Must touch it otherwise when you mount it to docker container, docker will create it as a directory
#------------------------------------------------------------------------------------------------------------
docker volume create shared_volume
monitored_logfile1="/app/${contname_uploader}.log"

#------------------------------------------------------------------------------------------------------------
# Extract and build logstash + scalyr_plugin docker image
# This step is important and necessary to simulate customer installing our gem into a logstash installation
#------------------------------------------------------------------------------------------------------------

agent_image="local-logstash-output-scalyr-image"
pushd $logstash_docker_context

perl -pi.bak -e "s{ORIGIN1_INFILE}{$monitored_logfile1}" pipeline/scalyr.conf
perl -pi.bak -e "s{SCALYR_API_KEY}{$SCALYR_API_KEY}" pipeline/scalyr.conf
perl -pi.bak -e "s{SCALYR_SERVER}{$SCALYR_SERVER}" pipeline/scalyr.conf
perl -pi.bak -e "s{COMPRESSION_TYPE}{$COMPRESSION_TYPE}" pipeline/scalyr.conf
perl -pi.bak -e "s{WORKER_COUNT}{$worker_count}" config/pipelines.yml

docker build -t ${agent_image} .

echo "Using scalyr.conf plugin config:"
echo ""
cat pipeline/scalyr.conf
echo ""
popd


#------------------------------------------------------------------------------------------------------------
# Launch Agent container (which begins gathering stdout logs)
#------------------------------------------------------------------------------------------------------------
docker run -d --name ${contname_agent} \
-e SCALYR_API_KEY=${SCALYR_API_KEY} -e SCALYR_SERVER=${SCALYR_SERVER} \
--mount source=shared_volume,target=/app \
${agent_image}

# Capture agent short container ID
agent_hostname=$(docker ps --format "{{.ID}}" --filter "name=$contname_agent")
echo "Logstash/plugin container ID == ${agent_hostname}"

#------------------------------------------------------------------------------------------------------------
# Launch Uploader container (writes to $monitored_logfile1, but needs to query Scalyr to verify agent liveness)
# You MUST provide scalyr server, api key and importantly, the agent_hostname container ID for the agent-liveness
# query to work (uploader container waits for agent to be alive before uploading data)
#------------------------------------------------------------------------------------------------------------
docker run -d --name ${contname_uploader} \
--mount source=shared_volume,target=/app \
${smoketest_image} \
bash -c "${smoketest_script} ${contname_uploader} ${max_wait} \
--mode uploader \
--scalyr_server ${SCALYR_SERVER} \
--read_api_key ${READ_API_KEY} \
--agent_hostname ${agent_hostname} \
--monitored_logfile $monitored_logfile1 \
--debug true"

# Capture uploader short container ID
uploader_hostname=$(docker ps --format "{{.ID}}" --filter "name=$contname_uploader")
echo "Uploader container ID == ${uploader_hostname}"

#------------------------------------------------------------------------------------------------------------
# Launch synchronous Verifier image
# Like the Uploader, the Verifier also waits for agent to be alive before uploading data
# Failure in this process will cause CI to report failure
#------------------------------------------------------------------------------------------------------------
docker run -it --name ${contname_verifier} \
--mount source=shared_volume,target=/app \
${smoketest_image} \
bash -c "${DOWNLOAD_SMOKE_TESTS_SCRIPT_COMMAND} ; ${smoketest_script} ${contname_verifier} ${max_wait} \
--mode verifier \
--scalyr_server ${SCALYR_SERVER} \
--read_api_key ${READ_API_KEY} \
--agent_hostname ${agent_hostname} \
--uploader_hostname ${uploader_hostname} \
--monitored_logfile $monitored_logfile1 \
--compression_type ${COMPRESSION_TYPE} \
--debug true"

kill_and_delete_docker_test_containers
