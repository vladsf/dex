#!/bin/bash

merged_branch=master

function abort() {
  echo $'\e[31m'"$@"$'\e[0m' >&2
  exit 1
}

ran_progress="false"

function progress() {
  if [ "$ran_progress" = "true" ]; then
    echo ""
  fi

  ran_progress="true"

  echo $'\e[1m'"$@"$'\e[0m'
}

set +x

if ! git remote | grep upstream >/dev/null; then
  git remote add upstream https://github.com/dexidp/dex
fi

mkdir ~/.ssh
ssh-keyscan -H github.com >> ~/.ssh/known_hosts
echo "$CONCOURSE_DEX_DEPLOY_KEY" > key
chmod 400 key

eval $(ssh-agent) >/dev/null 2>&1
trap "kill $SSH_AGENT_PID" EXIT
ssh-add key

git config --global user.email "ci@localhost"
git config --global user.name "CI Bot"

set -x
