#!/usr/bin/env bash

#export CONTAINERS_MACHINE_PROVIDER=applehv

podman machine init --volume /Users/venek001:/Users/venek001
podman machine start
