#!/bin/bash

set -euox pipefail

apt-get update \
&& apt-get install --yes \
  iproute2 \
  net-tools \
  curl \
  wget \
  python3 \
&& apt-get autoremove --yes \
&& apt-get clean \
&& rm -rf /var/lib/apt/lists/*
