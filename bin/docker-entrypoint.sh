#!/bin/bash

set -eo pipefail
shopt -s nullglob

# Strip `LOCALSTACK_` prefix in environment variables name; except LOCALSTACK_HOST and LOCALSTACK_HOSTNAME (deprecated)
source <(
  env |
  grep -v -e '^LOCALSTACK_HOSTNAME' |
  grep -v -e '^LOCALSTACK_HOST' |
  grep -v -e '^LOCALSTACK_[[:digit:]]' | # See issue #1387
  sed -ne 's/^LOCALSTACK_\([^=]\+\)=.*/export \1=${LOCALSTACK_\1}/p'
)

LOG_DIR=/var/lib/localstack/logs
test -d ${LOG_DIR} || mkdir -p ${LOG_DIR}

# activate the virtual environment
source /opt/code/localstack/.venv/bin/activate

# run runtime init hooks BOOT stage before starting localstack
test -d /etc/localstack/init/boot.d && python3 -m localstack.runtime.init BOOT

# run the localstack supervisor. it's important to run with `exec` and don't use pipes so signals are handled correctly
exec localstack-supervisor
