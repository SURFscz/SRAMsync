#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

import sys
import json
import ldap
import copy
import click
from config import Config
from datetime import datetime, timezone, timedelta


def dn2rdns(dn):
    rdns = {}
    r = ldap.dn.str2dn(dn)
    for rdn in r:
        a, v, _ = rdn[0]
        rdns.setdefault(a, []).append(v)
    return rdns


def init_ldap(config):
    """
    Initialization and binding an LDAP connection.
    """
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
    ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
    ldap_conn = ldap.initialize(config['uri'])
    ldap_conn.simple_bind_s(config['binddn'], config['passwd'])

    return ldap_conn


def get_previous_status(cfg):
    """
    Get the saved status from disk if it exits. Return an empty status otherwise.
    """
    status = { 'users': {}, 'groups': {} }

    try:
        with open(cfg['status_filename']) as json_file:
            status = json.load(json_file)
    except FileNotFoundError as e:
        pass

    return status


def generate_header(cfg):
    """
    Generate the first line of the resulting script. This includes the shebang,
    some comments and setting xtrace
    """
    output = cfg.getOutputDescriptor()

    print('################', file=output)
    print('#', file=output)
    print('#  Automatically generated file by cua-sync', file=output)
    print(f'#  Date: {datetime.now()}', file=output)
    print('#', file=output)
    print('################', file=output)
    print(file=output)
    print("set -o xtrace", file=output)
    print(file=output)


def process_user_data(cfg, service, co, status, new_status):
    """
    Process the CO user data as found in SRAM for the service.

    Collect the necessary information from SRAM such that shell commands can be
    generated that call for the respective sara_usertools commands with the
    collected information.

    The provided status is used to determine whether or not a user has already
    been processed in a previous run.

    While looping over all users, a new_status is maintained to reflect the to
    be situation of the CUA. This to be situation will be achieved after a
    successful run of the resulting script.
    """

    groups = cfg['cua']['groups']
    ldap_conn = cfg.getLDAPconnector()
    output = cfg.getOutputDescriptor()

    #  Check if there is at least one group that controls which users are
    #  allowed to login. If there are none, it's okay to use all known users.
    login_group = [ k for g in groups for k,v in g.items() if 'login_users' in v['attributes'] ]
    login_users = []
    l = len(login_group)
    if l >= 1:
        print(f'  Using group(s) {login_group} for allowing users to login.')
        for group in login_group:
            try:
                dns = ldap_conn.search_s(f"ou=Groups,o={service},dc=ordered,{cfg.getSRAMbasedn()}", ldap.SCOPE_ONELEVEL, f'(cn={group})')
                for _, entry in dns:
                    for member in entry['member']:
                        uid = dn2rdns(member)['uid'][0]
                        login_users.append(uid)
            except ldap.NO_SUCH_OBJECT:
                print(f'Warning: login group \'{group}\' has been defined but could not be found for CO \'{co}\'.')
        if len(login_users) == 0:
            return new_status

    try:
        dns = ldap_conn.search_s(f"ou=People,o={service},dc=ordered,{cfg.getSRAMbasedn()}", ldap.SCOPE_ONELEVEL, "(objectClass=person)")

        for _, entry in dns:
            uid = entry['uid'][0].decode('UTF-8')
            if login_users and uid not in login_users:
                continue
            givenname = entry['givenName'][0].decode('UTF-8')
            sn = entry['sn'][0].decode('UTF-8')
            user = f"sram-{co}-{uid}"
            mail = entry['mail'][0].decode('UTF-8')
            line=f"sram:{givenname}:{sn}:{user}:0:0:0:/bin/bash:0:0:{mail}:0123456789:zz:{cfg['cua']['servicename']}"
            new_status['users'][user] = {'line': line}
            print(f"## Adding user: {user}", file=output)
            user_status = status['users'].get(user)

            if user_status == None or user_status.get('line') != line:
                print(f'  Found new user: {user}')
                new_status['users'][user]['line'] = line
                print(f"{cfg['cua']['modify_user']} --list {user} ||", file=output)
                print(f"  {{\n    echo \"{line}\" | {cfg['cua']['add_user']} -f-\n    {cfg['cua']['modify_user']} --service sram:{service} {user}\n  }}\n", file=output)

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
                    print('      Adding public SSH key')
                    print(f'### SSH Public key: {key}', file=output)
                    print(f'{cfg["cua"]["modify_user"]} --ssh-public-key "{key}" {user}\n', file=output)

                for key in dropped_sshPublicKeys:
                    print(f'### Remove SSH Public key: {key}', file=output)
                    print(f'{cfg["cua"]["modify_user"]} -r --ssh-public-key "{key}" {user}\n', file=output)

    except ldap.NO_SUCH_OBJECT as e:
        print('The basedn does not exists.')

    return new_status


def process_group_data(cfg, service, org, co, status, new_status):
    """
    Process the CO group data as found in SRAM for the service. Only those
    groups that are defined in the configuration file are processed.

    Collect the necessary information from SRAM such that shell commands can be
    generated that call for the respective sara_usertools commands with the
    collected information.

    The provided status is used to determine whether or not a user has already
    been added to the group in a previous run.

    While looping over all users, a new_status is maintained to reflect the to
    be situation of the CUA. This to be situation will be achieved after a
    successful run of the resulting script.
    """
    output = cfg.getOutputDescriptor()
    ldap_conn = cfg.getLDAPconnector()

    for group in cfg['cua']['groups']:
        sram_group = list(group.keys())[0]
        tmp = list(group.values())[0]
        group_attributes = tmp['attributes']
        cua_group = tmp['destination']

        if 'ignore' in group_attributes:
            continue

        try:
            basedn = cfg.getSRAMbasedn()
            dns = ldap_conn.search_s(f"cn={sram_group},ou=Groups,o={service},dc=ordered,{basedn}", ldap.SCOPE_BASE, "(objectClass=groupOfMembers)")
            cua_group = f'{cua_group}'.format(**locals())  # The cua_group could contain an org reference
            line=f"sram_group:description:dummy:{cua_group}:0:0:0:/bin/bash:0:0:dummy:dummy:dummy:"

            # Create groups
            if cua_group not in status['groups']:
                status['groups'][cua_group] = { 'members': [], 'attributes': group_attributes }
                print(f'  Adding group: {cua_group}')
                print(f"## Adding group: {cua_group}", file=output)
                print(f"{cfg['cua']['modify_user']} --list {cua_group} ||", file=output)
                print(f"  {{\n    echo \"{line}\" | {cfg['cua']['add_user']} -f-\n  }}\n", file=output)

            if cua_group not in new_status['groups']:
                new_status['groups'][cua_group] = {'members': [], 'attributes': group_attributes}

            # Find members
            for dn, entry in dns:
                # Add members
                members = [m.decode('UTF-8') for m in entry['member']]
                for member in members:
                    m_uid = dn2rdns(member)['uid'][0]
                    user = f"sram-{co}-{m_uid}"
                    new_status['groups'][cua_group]['members'].append(user)
                    print(f"### Adding member: {user} to group {cua_group}", file=output)
                    if user not in status['groups'][cua_group]['members']:
                        if 'system_group' in group_attributes:
                            print(f'    Adding user {user} to system group {cua_group}')
                            print(f"{cfg['cua']['modify_user']} -a delena {cua_group} {user}\n", file=output)
                        elif 'project_group' in group_attributes:
                            print(f'    Adding user {user} to project group {cua_group}')
                            print(f"{cfg['cua']['modify_user']} -g {cua_group} {user}\n", file=output)
                        else:
                            raise ValueError(f'group_type has unknown value: {group_type}')
        except ldap.NO_SUCH_OBJECT:
            print(f'  Warning: service \'{service}\' does not contain group \'{sram_group}\'')
        except:
            raise

    return new_status


def add_missing_entries_to_cua(cfg, status, new_status):
    """
    Determine which entries in the SRAM LDAP have not been processed before.

    This is the main loop. It loops over all services that are in the SRAM LDAP
    for the service provider. For each service it is determined if it needs to
    be added to the CUA. The work in determining what is defined in the SRAM
    LDAP is split into two: i) processing user data and ii) processing group
    data.

    The current state the CUA should be in is tracked in new_status, while
    status is the previous known status of the CUA.
    """

    generate_header(cfg)

    ldap_conn = cfg.getLDAPconnector()
    basedn = cfg.getSRAMbasedn()
    dns = ldap_conn.search_s(f"dc=ordered,{basedn}", ldap.SCOPE_ONELEVEL, "(&(o=*)(ObjectClass=organization))")

    for _, entry in dns:
        output = cfg.getOutputDescriptor()

        service = entry['o'][0].decode('UTF-8')
        org, co = service.split('.')
        print(f"\n# service: {service}", file=output)
        print(f'Processing CO: {co}')

        new_status = process_user_data(cfg, service, co, status, new_status)
        new_status = process_group_data(cfg, service, org, co, status, new_status)

    return new_status


def remove_superfluous_entries_from_cua(cfg, status, new_status):
    """
    Remove entries in the CUA based on the difference between status and
    new_status.
    """

    output = cfg.getOutputDescriptor()
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

            print(f'# Remove {user} from {group}', file=output)
            if 'project_group' in new_groups[group]['attributes']:
                print(f'{cfg["cua"]["modify_user"]} -r -g {group} {user}', file=output)
            if 'system_group' in new_groups[group]['attributes']:
                print(f'{cfg["cua"]["modify_user"]} -r -a delena {group} {user}', file=output)

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
                    print(f'# removing {user} from {group} after grace period ended. Grace period started on {grace_start}', file=output)
                    print(f'{modifyuser} -r -a delena {group} {user}', file=output)
    except KeyError as e:
        sys.exit(f"Missing element from config: {e}")

    return new_status


def get_generator(cfg):
    generator_name = cfg['cua']['generator']['generator_type']
    generator_module = __import__(generator_name)
    generator_class = getattr(generator_module, generator_name)
    generator = generator_class(
                {
                    'servicename': cfg['cua']['servicename'],
                    **cfg['cua']['generator']['input']
                }
            )

    return generator


def get_event_handler(cfg, generator):
    event_name = cfg['cua']['generator']['event_handler']
    event_module = __import__(event_name)
    event_class = getattr(event_module, event_name)
    event_handler = event_class(generator)

    return event_handler


@click.command()
@click.help_option()
@click.version_option()
@click.argument('configuration', type=click.Path(exists=True, dir_okay=False))
@click.argument('output', type=click.Path(writable=True, allow_dash=True))
def cli(configuration, output):
    """
    Synchronisation between the SRAM LDAP and the CUA

    cua-sync takes an configuration file which describes a source LDAP with
    which the CUA must be synchronized. This configuration file also describes
    which groups need to be considered for synchronisation.

    During a synchronisation run, a status is kept. It reflects the current
    state of what has been done in order to synchronize the CUA. However, the
    actual actions to make changes to the CUA are diverted to a generated
    script file. Once cua-sync has finished running, this resulting script file
    must be executed in order to finish the syncing process.

    The generated status file is written to disk to keep this history. Upon a
    next run, the previous known status is read and used to determine if
    additional actions are required to keep the CUA in sync the SRAM. Thus the
    status is used to prevent adding things to the CUA when that already has
    happened.

    CONFIGURATION: Path to a configuration file. OUTPUT: Path of the resulting
    script.
    """

    try:
        new_status = { 'users': {}, 'groups': {} }
        cfg = Config(configuration)

        generator = get_generator(cfg)
        event_handler = get_event_handler(cfg, generator)

        ldap_conn = init_ldap(cfg['ldap'])
        cfg.setLDAPconnector(ldap_conn)
        status = get_previous_status(cfg)
        new_status = add_missing_entries_to_cua(cfg, status, new_status)
        new_status = remove_superfluous_entries_from_cua(cfg, status, new_status)

        with open(cfg['status_filename'], "w") as status_file:
            json.dump(new_status, status_file, indent=4)
    except IOError as e:
        print(e)
    except ldap.NO_SUCH_OBJECT as e:
        if 'desc' in e.args[0]:
            print(e.args[0]['desc'])
    except ldap.INVALID_CREDENTIALS:
        print('Invalid credentials. Please check your configuration file.')
    except ModuleNotFoundError as e:
        print(f'{e}. Please check your config file.')
