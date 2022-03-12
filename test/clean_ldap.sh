#!/usr/bin/env bash

basedn="dc=mt-doom,dc=services,dc=sram,dc=surf,dc=nl"
declare -a subtrees=("flat" "ordered")

for subtree in ${subtrees[@]}; do
    dn="dc=$subtree,$basedn"
    echo "Deleting: $dn"
    ldapdelete -H ldap://localhost:3389 -D 'cn=admin,dc=mt-doom,dc=services,dc=sram,dc=surf,dc=nl' -w mellon -r "$dn"
done

