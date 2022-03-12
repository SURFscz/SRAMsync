#!/usr/bin/env bash

podman run --rm  --detach \
    --hostname ldap.example.org \
    --env LDAP_TLS=false \
    --env LDAP_LOG_LEVEL=0x100 \
    --env LDAP_BACKEND=mdb \
    --env LDAP_ORGANISATION=SURF \
    --env LDAP_DOMAIN=mt-doom.services.sram.surf.nl \
    --env LDAP_BASE_DN=dc=mt-doom,dc=services,dc=sram,dc=surf,dc=nl \
    --env LDAP_ADMIN_PASSWORD=mellon \
    --env LDAP_CONFIG_PASSWORD=mellon \
    --env DISABLE_CHOWN=true\
    --env LDAP_REMOVE_CONFIG_AFTER_SETUP=false \
    --name ldap \
    --publish 3389:389 \
    --volume $PWD/test/ldif:/container/service/slapd/assets/config/bootstrap/ldif/custom:Z \
    docker.io/osixia/openldap --copy-service --loglevel debug \
