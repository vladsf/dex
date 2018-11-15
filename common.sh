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
