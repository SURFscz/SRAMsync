#!/usr/bin/env python3
# -*- coding: future_fstrings -*-

from datetime import datetime, timedelta, timezone
import json

import click
import ldap

from config import Config


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
    ldap_conn = ldap.initialize(config["uri"])
    ldap_conn.simple_bind_s(config["binddn"], config["passwd"])

    return ldap_conn


def get_previous_status(cfg):
    """
    Get the saved status from disk if it exits. Return an empty status otherwise.
    """
    status = {"users": {}, "groups": {}}

    try:
        with open(cfg["status_filename"]) as json_file:
            status = json.load(json_file)
    except FileNotFoundError as e:
        pass

    return status


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

    ldap_conn = cfg.getLDAPconnector()
    event_handler = cfg.event_handler

    #  Check if there is at least one group that controls which users are
    #  allowed to login. If there are none, it's okay to use all known users.
    login_group = [
        group
        for groups in cfg["sync"]["groups"]
        for group, v in groups.items()
        if "login_users" in v["attributes"]
    ]
    login_users = []
    l = len(login_group)
    if l >= 1:
        print(f'  Using group(s) \'{", ".join(login_group)}\' for allowing users to login.')
        for group in login_group:
            try:
                dns = ldap_conn.search_s(
                    f"ou=Groups,o={service},dc=ordered,{cfg.getSRAMbasedn()}",
                    ldap.SCOPE_ONELEVEL,
                    f"(cn={group})",
                )
                for _, entry in dns:
                    for member in entry["member"]:
                        uid = dn2rdns(member)["uid"][0]
                        login_users.append(uid)
            except ldap.NO_SUCH_OBJECT:
                print(
                    f"Warning: login group '{group}' has been defined but could not be found for CO '{co}'."
                )
        if len(login_users) == 0:
            return new_status

    try:
        dns = ldap_conn.search_s(
            f"ou=People,o={service},dc=ordered,{cfg.getSRAMbasedn()}",
            ldap.SCOPE_ONELEVEL,
            "(objectClass=person)",
        )

        for _, entry in dns:
            uid = entry["uid"][0].decode("UTF-8")
            if login_users and uid not in login_users:
                continue
            givenname = entry["givenName"][0].decode("UTF-8")
            sn = entry["sn"][0].decode("UTF-8")
            user = f"sram-{co}-{uid}"
            mail = entry["mail"][0].decode("UTF-8")
            line = f"sram:{givenname}:{sn}:{user}:0:0:0:/bin/bash:0:0:{mail}:0123456789:zz:{cfg['sync']['servicename']}"
            new_status["users"][user] = {"line": line}
            user_status = status["users"].get(user)

            if user_status == None or user_status.get("line") != line:
                print(f"  Found new user: {user}")
                new_status["users"][user]["line"] = line
                event_handler.add_new_user(givenname, sn, user, mail)

            if "sshPublicKey" in entry:
                raw_sshPublicKeys = entry["sshPublicKey"]
                sshPublicKeys = set([raw_sshPublicKeys[0].decode("UTF-8").rstrip()])
                for key in raw_sshPublicKeys[1:]:
                    sshPublicKeys = sshPublicKeys | key.decode("UTF-8").rstrip()

                known_sshPublicKeys = set()
                if user_status and "sshPublicKey" in user_status:
                    known_sshPublicKeys = set(user_status["sshPublicKey"])
                new_status["users"][user]["sshPublicKey"] = list(sshPublicKeys)

                new_sshPublicKeys = sshPublicKeys - known_sshPublicKeys
                dropped_sshPublicKeys = known_sshPublicKeys - sshPublicKeys

                for key in new_sshPublicKeys:
                    print("    Adding public SSH key")
                    event_handler.add_public_ssh_key(user, key)

                for key in dropped_sshPublicKeys:
                    print("    Removing public SSH key")
                    event_handler.delete_public_ssh_key(user, key)

    except ldap.NO_SUCH_OBJECT as e:
        print("The basedn does not exists.")

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

    event_handler = cfg.event_handler
    ldap_conn = cfg.getLDAPconnector()

    for group in cfg["sync"]["groups"]:
        sram_group = list(group.keys())[0]
        tmp = list(group.values())[0]
        group_attributes = tmp["attributes"]
        cua_group = tmp["destination"]

        if "ignore" in group_attributes:
            continue

        try:
            basedn = cfg.getSRAMbasedn()
            dns = ldap_conn.search_s(
                f"cn={sram_group},ou=Groups,o={service},dc=ordered,{basedn}",
                ldap.SCOPE_BASE,
                "(objectClass=groupOfMembers)",
            )
            cua_group = f"{cua_group}".format(**locals())  # The cua_group could contain an org reference

            # Create groups
            if cua_group not in status["groups"]:
                status["groups"][cua_group] = {
                    "members": [],
                    "attributes": group_attributes,
                }
                print(f"  Adding group: {cua_group}")
                event_handler.add_new_group(cua_group)

            if cua_group not in new_status["groups"]:
                new_status["groups"][cua_group] = {
                    "members": [],
                    "attributes": group_attributes,
                }

            # Find members
            for _, entry in dns:
                # Add members
                members = [m.decode("UTF-8") for m in entry["member"]]
                for member in members:
                    m_uid = dn2rdns(member)["uid"][0]
                    user = f"sram-{co}-{m_uid}"
                    new_status["groups"][cua_group]["members"].append(user)
                    # print(f"### Adding member: {user} to group {cua_group}", file=output)
                    if user not in status["groups"][cua_group]["members"]:
                        event_handler.add_user_to_group(cua_group, user, group_attributes)
        except ldap.NO_SUCH_OBJECT:
            print(f"  Warning: service '{service}' does not contain group '{sram_group}'")
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

    event_handler = cfg.event_handler
    ldap_conn = cfg.getLDAPconnector()
    basedn = cfg.getSRAMbasedn()
    dns = ldap_conn.search_s(
        f"dc=ordered,{basedn}",
        ldap.SCOPE_ONELEVEL,
        "(&(o=*)(ObjectClass=organization))",
    )

    for _, entry in dns:
        service = entry["o"][0].decode("UTF-8")
        org, co = service.split(".")
        event_handler.start_of_service_processing(co)
        print(f"Processing CO: {co}")

        new_status = process_user_data(cfg, service, co, status, new_status)
        new_status = process_group_data(cfg, service, org, co, status, new_status)

    return new_status


def remove_graced_users(cfg, status, new_status) -> dict:
    if "groups" not in new_status:
        return new_status

    event_handler = cfg.event_handler

    for group, v in status["groups"].items():
        if "graced_users" in v:
            print(f"Checking graced users for group: {group}")
            for user, grace_until_str in v["graced_users"].items():
                grace_until = datetime.strptime(grace_until_str, "%Y-%m-%d %H:%M:%S%z")
                now = datetime.now(timezone.utc)
                if now > grace_until:
                    # The graced info for users is in status initially and needs to be
                    # copied over to new_status if it needs to be preserved. Not doing
                    # so automatically disregards this information automatically and
                    # it is the intended behaviour
                    print(f"Grace time ended for user {user} in {group}")
                    event_handler.remove_graced_user(user)
                else:
                    if "graced_users" not in new_status["groups"][group]:
                        new_status["groups"][group]["graced_users"] = {}
                    new_status["groups"][group]["graced_users"][user] = grace_until_str

                    remaining_time = grace_until - now
                    print(f"{user} from {group} has {remaining_time} left of its grace time.")
    return new_status


def remove_user_from_group(cfg, status, new_status) -> dict:
    event_handler = cfg.event_handler

    for group, v in status["groups"].items():
        removed_users = [user for user in v["members"] if user not in new_status["groups"][group]["members"]]

        for user in removed_users:
            if "grace_period" in v["attributes"]:
                if "grace" in cfg["sync"] and group in cfg["sync"]["grace"]:
                    grace_until = datetime.now(timezone.utc) + timedelta(
                        cfg["sync"]["grace"][group]["grace_period"]
                    )
                    remaining_time = grace_until - datetime.now(timezone.utc)
                    print(
                        f'User "{user}" has been removed but not deleted due to grace time. Remaining time: {remaining_time}'
                    )
                    new_status["groups"][group]["graced_users"] = {
                        user: datetime.strftime(grace_until, "%Y-%m-%d %H:%M:%S%z")
                    }
                else:
                    print(f'Grace has not been defined for group "{group}" in the configuration file.')
            else:
                event_handler.remove_user_from_group(group, v["attributes"], user)

    return new_status


def remove_superfluous_entries_from_cua(cfg, status, new_status):
    """
    Remove entries in the CUA based on the difference between status and
    new_status.
    """

    new_status = remove_graced_users(cfg, status, new_status)
    new_status = remove_user_from_group(cfg, status, new_status)

    return new_status


def get_generator(cfg):
    generator_name = cfg["sync"]["generator"]["generator_type"]
    generator_module = __import__(generator_name)
    generator_class = getattr(generator_module, generator_name)
    generator = generator_class(
        {"servicename": cfg["sync"]["servicename"], **cfg["sync"]["generator"]["input"]}
    )

    return generator


def get_event_handler(cfg, generator):
    event_name = cfg["sync"]["generator"]["event_handler"]
    event_module = __import__(event_name)
    event_class = getattr(event_module, event_name)
    event_handler = event_class(generator)

    return event_handler


@click.command()
@click.help_option()
@click.version_option()
@click.argument("configuration", type=click.Path(exists=True, dir_okay=False))
def cli(configuration):
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
        new_status = {"users": {}, "groups": {}}
        cfg = Config(configuration)

        generator = get_generator(cfg)
        event_handler = get_event_handler(cfg, generator)
        cfg.setEventHandler(event_handler)

        ldap_conn = init_ldap(cfg["sram"])
        cfg.setLDAPconnector(ldap_conn)
        status = get_previous_status(cfg)
        new_status = add_missing_entries_to_cua(cfg, status, new_status)
        new_status = remove_superfluous_entries_from_cua(cfg, status, new_status)

        event_handler.finialize()

        with open(cfg["status_filename"], "w") as status_file:
            json.dump(new_status, status_file, indent=2)
    except IOError as e:
        print(e)
    except ldap.NO_SUCH_OBJECT as e:
        if "desc" in e.args[0]:
            print(e.args[0]["desc"])
    except ldap.INVALID_CREDENTIALS:
        print("Invalid credentials. Please check your configuration file.")
    except ModuleNotFoundError as e:
        print(f"{e}. Please check your config file.")
