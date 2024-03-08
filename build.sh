#!/usr/bin/env bash

CONTAINER_NAME=openldap

if [ "$(buildah containers --noheading --filter "name=$CONTAINER_NAME" --format '{{.ContainerName}}')" == "$CONTAINER_NAME" ]; then
	echo "Remove container: $CONTAINER_NAME"
	buildah rm $CONTAINER_NAME
fi

container=$(buildah --name openldap from alpine:latest)
buildah config --label Name=openldap "$container"
buildah config --author "Gerben Venekamp" "$container"

buildah run "$container" apk update
buildah run "$container" apk add openldap-back-mdb openldap

buildah commit --squash "$container" 'openldap'
