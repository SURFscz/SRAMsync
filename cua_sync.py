#!/usr/bin/env python3
# -*- coding: future_fstrings -*-


import sys
import yaml
import json
import ldap
import copy
from datetime import datetime, timezone, timedelta

def dn2rdns(dn):
    rdns = {}
    r = ldap.dn.str2dn(dn)
    for rdn in r:
        a, v, t = rdn[0]
        rdns.setdefault(a, []).append(v)
    return rdns


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

    status_filename = config['status_filename']
except KeyError as e:
    sys.exit(f"Missing element from config: {e}")

# Setup LDAP connection
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
ldap_conn = ldap.initialize(uri)
ldap_conn.simple_bind_s(binddn, passwd)

new_status = { 'users': {}, 'groups': {} }

try:
    with open(status_filename) as json_file:
        status = json.load(json_file)
except:
    status = { 'users': {}, 'groups': {} }


print("#!/bin/bash")
print()
print("set -o xtrace")
# Find organisation dns (o = ...)
try:
    dns = ldap_conn.search_s(f"dc=ordered,{basedn}", ldap.SCOPE_ONELEVEL, "(&(o=*)(ObjectClass=organization))")
except:
    dns = []
if len(dns):
    for dn, entry in dns:
        #print(f"dn: {dn}")
        service = entry['o'][0].decode('UTF-8')
        org, co = service.split('.')
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
                new_status['users'][user] = {'line': line}
                print(f"  #user {user}")
                user_status = status.get(user)

                if user_status == None or user_status.get('line') != line:
                    new_status['users'][user]['line'] = line
                    print(f"{modifyuser} --list {user} ||")
                    print(f"  {{\n    echo \"{line}\" | {adduser} -f-\n    {modifyuser} --service sram:{service} {user}\n  }}\n")

                if 'sshPublicKey' in entry:
                    raw_sshPublicKeys = entry['sshPublicKey']
                    sshPublicKeys = set([raw_sshPublicKeys[0].decode('UTF-8').rstrip()])
                    for key in raw_sshPublicKeys[1:]:
                        sshPublicKeys = sshPublicKeys | key.decode('UTF-8').rstrip()

                    known_sshPublicKeys = set()
                    if user_status and 'sshPublicKey' in user_status:
                        known_sshPublicKeys = set(user_status['sshPublicKey'])
                    new_status['users'][user]['sshPublicKey'] = list(sshPublicKeys)

                    new_sshPublicKeys = sshPublicKeys - known_sshPublicKeys
                    dropped_sshPublicKeys = known_sshPublicKeys - sshPublicKeys

                    for key in new_sshPublicKeys:
                        print(f'  # SSH Public key: {key}')
                        print(f'{modifyuser} --ssh-public-key "{key}" {user}')

        # Find groups in service
        for group in cua_groups:
            sram_group = list(group.keys())[0]
            tmp = list(group.values())[0]
            group_def, cua_group = tmp.split(':')
            tmp = group_def.split('+', 1)
            group_type = tmp[0]
            group_attributes = tmp[1:]

            if group_type == 'ign':
                continue

            if group_type == 'sys':
                group_attributes.append('system_group')
            if group_type == 'prj':
                group_attributes.append('project_group')

            cua_group = f'{cua_group}'.format(**locals())
            print(f"  #group: {cua_group}")
            # Create groups
            line=f"sram_group:description:dummy:{cua_group}:0:0:0:/bin/bash:0:0:dummy:dummy:dummy:"
            if cua_group not in new_status['groups']:
                new_status['groups'][cua_group] = {'members': [], 'attributes': group_attributes}
            if not isinstance(status.get(cua_group), list):
                print(f"{modifyuser} --list {cua_group} ||")
                print(f"  {{\n    echo \"{line}\" | {adduser} -f-\n  }}\n")

            # Find members
            try:
                dns = ldap_conn.search_s(f"cn={sram_group},ou=Groups,o={service},dc=ordered,{basedn}", ldap.SCOPE_BASE, "(objectClass=groupOfMembers)")
            except:
                dns = []
            if len(dns):
                for dn, entry in dns:
                    # Add members
                    members = [m.decode('UTF-8') for m in entry['member']]
                    for member in members:
                        m_uid = dn2rdns(member)['uid'][0]
                        user = f"sram-{co}-{m_uid}"
                        new_status['groups'][cua_group]['members'].append(user)
                        print(f"    #member: {user}")
                        if user not in status.get(cua_group, []):
                            if group_type == 'sys':
                                print(f"{modifyuser} -a delena {cua_group} {user}\n")
                            elif group_type == 'prj':
                                print(f"{modifyuser} -g {cua_group} {user}\n")
                            else:
                                raise ValueError

new_groups = new_status['groups']
groups = status['groups']

for group, values in groups.items():
    if 'graced' in values:
        if 'graced' in new_groups[group]:
            new_groups[group]['graced'] = {**new_groups[group]['graced'], **groups[group]['graced']}
        else:
            new_groups[group]['graced'] = groups[group]['graced']

removes = {k: set(groups[k]['members']) - set(new_groups[k]['members']) for k in groups if set(groups[k]['members']) - set(new_groups[k]['members'])}
for group, users in removes.items():
    for user in users:
        if 'grace' in new_groups[group]['attributes']:
            # new_groups[group]['graced'] = {user: datetime.now(timezone.utc).isoformat()}
            new_groups[group]['graced'] = {user: datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z')}
            continue

        print(f'# Remove {user} from {group}')
        if 'project_group' in new_groups[group]['attributes']:
            print(f'{modifyuser} -r -g {group} {user}')
        if 'system_group' in new_groups[group]['attributes']:
            print(f'{modifyuser} -r -a delena {group} {user}')

removes = {k: new_groups[k] for k in new_groups if 'graced' in new_groups[k]}
if removes != {} and 'grace' not in cua:
    sys.exit(f"Missing element from config: grace")

tmp_status = copy.deepcopy(new_status)
try:
    for group, values in removes.items():
        grace_period = timedelta(days=cua['grace'][group]['grace_period'])
        for user, grace_start in values['graced'].items():
            grace_start = datetime.strptime(grace_start, '%Y-%m-%dT%H:%M:%S.%f%z')
            if grace_start + grace_period < datetime.now(timezone.utc):
                del tmp_status['groups'][group]['graced'][user]
                print(f'# removing {user} from {group} after grace period ended. Grace period started on {grace_start}')
                print(f'{modifyuser} -r -a delena {group} {user}')
except KeyError as e:
    sys.exit(f"Missing element from config: {e}")

new_status = tmp_status

with open(status_filename, 'w') as outfile:
    json.dump(new_status, outfile, indent=4)
