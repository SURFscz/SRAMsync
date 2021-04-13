#!/usr/bin/env python3
# -*- coding: future_fstrings -*-


import sys
import yaml
import json
import ldap

# Load configuration
if len(sys.argv) < 2:
    sys.exit(sys.argv[0] + "  <config.yml>")

with open(sys.argv[1]) as f:
    config = yaml.safe_load(f)

try:
    src = config['ldap']
    basedn = src['basedn']
    uri    = src['uri']
    binddn = src['binddn']
    passwd = src['passwd']

    cua = config['cua']
    adduser = cua['add']
    modifyuser = cua['modify']
    cua_groups = cua['groups']
except KeyError as e:
    sys.exit(f"Missing element from config: {e}")

# Setup LDAP connection
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
ldap_conn = ldap.initialize(uri)
ldap_conn.simple_bind_s(binddn, passwd)

new_status ={}
try:
    with open('status.json') as json_file:
        status = json.load(json_file)
except:
    status = {}

def dn2rdns(dn):
    rdns = {}
    r = ldap.dn.str2dn(dn)
    for rdn in r:
        a, v, t = rdn[0]
        rdns.setdefault(a, []).append(v)
    return rdns

print("#!/bin/bash")
# Find organisation dns (o = ...)
try:
    dns = ldap_conn.search_s(f"dc=ordered,{basedn}", ldap.SCOPE_ONELEVEL, "(&(o=*)(ObjectClass=organization))")
except:
    dns = []
if len(dns):
    for dn, entry in dns:
        #print(f"dn: {dn}")
        service = entry['o'][0].decode('UTF-8')
        co = service.split('.')[1]
        project_name = f"sram-{co}"
        print(f"\n#service: {service}")

        # Find users
        try:
            dns = ldap_conn.search_s(f"ou=People,o={service},dc=ordered,{basedn}", ldap.SCOPE_ONELEVEL, "(objectClass=person)")
        except:
            dns = []
        if len(dns):
            for dn, entry in dns:
                #print(f"dn: {dn}")
                givenname = entry['uid'][0].decode('UTF-8')
                sn = entry['sn'][0].decode('UTF-8')
                uid = entry['uid'][0].decode('UTF-8')
                user = f"sram-{co}-{uid}"
                mail = entry['mail'][0].decode('UTF-8')
                line=f"sram:{givenname}:{sn}:{user}:0:0:0:/bin/bash:0:0:{mail}:0123456789:zz:spider_login"
                new_status[user]=line
                print(f"  #user {user}")
                if status.get(user) != line:
                    print(f"{modifyuser} --list {user} ||")
                    print(f"  {{\n    echo \"{line}\" | {adduser} -f-\n    {modifyuser} --service sram:{service} {user}\n  }}\n")

        # Find groups in service
        for group in cua_groups:
            cua_group = f"{project_name}-{group}"
            print(f"  #group: {cua_group}")
            # Create groups
            line=f"sram_group:description:dummy:{cua_group}:0:0:0:/bin/bash:0:0:dummy:dummy:dummy:"
            new_status[cua_group] = []
            if not isinstance(status.get(cua_group), list):
                print(f"{modifyuser} --list {cua_group} ||")
                print(f"  {{\n    echo \"{line}\" | {adduser} -f-\n  }}\n")

            # Find members
            try:
                dns = ldap_conn.search_s(f"cn={group},ou=Groups,o={service},dc=ordered,{basedn}", ldap.SCOPE_BASE, "(objectClass=groupOfMembers)")
            except:
                dns = []
            if len(dns):
                for dn, entry in dns:
                    # Add members
                    members = [m.decode('UTF-8') for m in entry['member']]
                    for member in members:
                        m_uid = dn2rdns(member)['uid'][0]
                        user = f"sram-{co}-{m_uid}"
                        new_status[cua_group].append(user)
                        print(f"    #member: {user}")
                        if user not in status.get(cua_group, []):
                            print(f"{modifyuser} -g {cua_group} {user}\n")

removes = { k : status[k] for k in set(status) - set(new_status) }
for user in removes:
    print(f"#{user} remove")
    print(f"{modifyuser} --list {user} &&")
    print(f"  {modifyuser} --lock {user}")

with open('status.json', 'w') as outfile:
    json.dump(new_status, outfile, indent=4)
    pass
