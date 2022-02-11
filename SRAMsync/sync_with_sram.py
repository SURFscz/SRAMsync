#!/usr/bin/env python3

import importlib
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import click
import click_logging
import jsonschema.exceptions
import ldap

from .common import render_templated_string
from .config import Config
from .SRAMlogger import logger

#  By defaukt click does not offer the short '-h' option.
click_ctx_settings = dict(help_option_names=["-h", "--help"])

#  Adjust some of the default of click_logging.
click_logging_options = {
    "default": "WARNING",
    "metavar": "level",
    "help": "level should be one of: CRITICAL, ERROR, WARNING, INFO or DEBUG.",
}


class ConfigValidationError(jsonschema.exceptions.ValidationError):
    def __init__(self, exception, path):
        self.path = path
        self.exception = exception


class MultipleLoginGroups(Exception):
    pass


class PasswordNotFound(Exception):
    def __init__(self, msg):
        self.msg = msg


def dn2rdns(dn):
    rdns = {}
    r = ldap.dn.str2dn(dn)
    for rdn in r:
        a, v, _ = rdn[0]
        rdns.setdefault(a, []).append(v)
    return rdns


def get_ldap_passwd(config, service):
    if "SRAM_LDAP_PASSWD" in os.environ:
        return os.environ["SRAM_LDAP_PASSWD"]

    if "passwd" in config:
        return config["passwd"]

    try:
        with open(config["passwd_file"]) as fd:
            passwds = json.load(fd)
            try:
                return passwds[service]
            except KeyError:
                raise PasswordNotFound(f"SRAM LDAP password not found in {config['passwd_file']}")
    except KeyError:
        pass
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Password file not found: '{config['passwd_file']}'")

    raise PasswordNotFound("SRAM LDAP password not found. Check your configuration or set SRAM_LDAP_PASSWD.")


def init_ldap(config, service):
    """
    Initialization and binding an LDAP connection.
    """
    logger.debug(f"LDAP: connecting to: {config['uri']}")
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
    ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
    ldap_conn = ldap.initialize(config["uri"])
    passwd = get_ldap_passwd(config, service)
    ldap_conn.simple_bind_s(config["binddn"], passwd)
    logger.debug("LDAP: connected")
    return ldap_conn


def get_previous_status(cfg):
    """
    Get the saved status from disk if it exits. Return an empty status otherwise.
    """
    status = {"users": {}, "groups": {}}

    if "provisional_status_filename" in cfg and os.path.isfile(cfg["provisional_status_filename"]):
        logger.warning(f"Found unexpected provisional status file: {cfg['provisional_status_filename']}.")
        logger.warning("Possible reason is that the generated script has not been run yet.")
        logger.warning("It is okay to continue this sync and generate a new up-to-date script.")

    filename = render_templated_string(cfg["status_filename"], service=cfg["service"])
    try:
        with open(filename) as json_file:
            status = json.load(json_file)
    except FileNotFoundError as e:
        pass

    return status


def is_user_eligible(uid, login_users, entry):
    """
    Check if the user (uid) is eligible for using the service. There are two
    ways to determine it. i) if the users is found to be part of the
    login_users. ii) if the voPersonStatus is set for the user.

    If no login_users are defined nor is the voPersonStatus used, the user is
    always eligible.
    """
    if login_users and uid not in login_users:
        return False

    if "voPersonStatus" in entry:
        voPersonStatus = entry["voPersonStatus"][0].decode("UTF-8")
        if voPersonStatus != "active":
            return False

    return True


def get_login_users(cfg, service, co):
    """
    Check if there is at least one group that controls which users are
    allowed to login. If there are none, it's okay to use all known users.
    """
    ldap_conn = cfg.getLDAPconnector()

    login_groups = [group for group, v in cfg["sync"]["groups"].items() if "login_users" in v["attributes"]]
    login_users = []
    l = len(login_groups)

    if l > 1:
        raise MultipleLoginGroups()
    elif l == 1:
        group = login_groups[0]
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
            logger.warning(f"login group '{group}' has been defined but could not be found for CO '{co}'.")

    return login_users


def process_user_data(cfg, fq_co, co, status, new_status):
    """
    Process the CO user data as found in SRAM for the service.

    Collect the necessary information from SRAM such that shell commands can be
    generated that call for the respective sara_usertools commands with the
    collected information.

    The provided status is used to determine whether or not a user has already
    been processed in a previous run.

    While looping over all users, a new_status is maintained to reflect the to
    be situation of the destination LDAP. This to be situation will be achieved
    after a successful run of the resulting script.
    """

    ldap_conn = cfg.getLDAPconnector()
    event_handler = cfg.event_handler
    group = f"{cfg['service']}_login"

    login_users = get_login_users(cfg, fq_co, co)

    try:
        dns = ldap_conn.search_s(
            f"ou=People,o={fq_co},dc=ordered,{cfg.getSRAMbasedn()}",
            ldap.SCOPE_ONELEVEL,
            "(objectClass=person)",
        )

        for _, entry in dns:
            uid = entry["uid"][0].decode("UTF-8")
            if is_user_eligible(uid, login_users, entry):
                givenname = entry["givenName"][0].decode("UTF-8")
                sn = entry["sn"][0].decode("UTF-8")
                user = render_templated_string(cfg["sync"]["users"]["rename_user"], co=co, uid=uid)
                mail = entry["mail"][0].decode("UTF-8")

                new_status["users"][user] = {}
                if user not in status["users"]:
                    logger.debug(f"  Found new user: {user}")
                    event_handler.add_new_user(group, givenname, sn, user, mail)

                if "sshPublicKey" in entry:
                    raw_sshPublicKeys = entry["sshPublicKey"]
                    sshPublicKeys = set([raw_sshPublicKeys[0].decode("UTF-8").rstrip()])
                    for key in raw_sshPublicKeys[1:]:
                        sshPublicKeys = sshPublicKeys | {key.decode("UTF-8").rstrip()}

                    known_sshPublicKeys = set()
                    if user in status["users"] and "sshPublicKey" in status["users"][user]:
                        known_sshPublicKeys = set(status["users"][user]["sshPublicKey"])
                    new_status["users"][user]["sshPublicKey"] = list(sshPublicKeys)

                    new_sshPublicKeys = sshPublicKeys - known_sshPublicKeys
                    dropped_sshPublicKeys = known_sshPublicKeys - sshPublicKeys

                    for key in new_sshPublicKeys:
                        logger.debug(f"    Adding public SSH key: {key[:50]}…")
                        event_handler.add_public_ssh_key(user, key)

                    for key in dropped_sshPublicKeys:
                        logger.debug(f"    Removing public SSH key: {key[:50]}…")
                        event_handler.delete_public_ssh_key(user, key)

    except ldap.NO_SUCH_OBJECT as e:
        logger.error("The basedn does not exists.")

    return new_status


def process_group_data(cfg, fq_co, org, co, status, new_status):
    """
    Process the CO group data as found in SRAM for the service. Only those
    groups that are defined in the configuration file are processed.

    Collect the necessary information from SRAM such that shell commands can be
    generated that call for the respective sara_usertools commands with the
    collected information.

    The provided status is used to determine whether or not a user has already
    been added to the group in a previous run.

    While looping over all users, a new_status is maintained to reflect the to
    be situation of the destination LDAP. This to be situation will be achieved
    after a successful run of the resulting script.
    """

    event_handler = cfg.event_handler
    ldap_conn = cfg.getLDAPconnector()
    service = cfg["service"]  # service might be accessed indirectly

    for sram_group, v in cfg["sync"]["groups"].items():
        group_attributes = v["attributes"]
        dest_group_name = v["destination"]

        if "ignore" in group_attributes:
            continue

        try:
            basedn = cfg.getSRAMbasedn()
            dns = ldap_conn.search_s(
                f"cn={sram_group},ou=Groups,o={fq_co},dc=ordered,{basedn}",
                ldap.SCOPE_BASE,
                "(objectClass=groupOfMembers)",
            )
            # The dest_group_name could contain an org reference
            dest_group_name = render_templated_string(dest_group_name, service=service, org=org, co=co)

            # Create groups
            if dest_group_name not in status["groups"]:
                status["groups"][dest_group_name] = {
                    "members": [],
                    "attributes": group_attributes,
                }
                logger.debug(f"  Adding group: {dest_group_name}")
                event_handler.add_new_group(dest_group_name, group_attributes)

            if dest_group_name not in new_status["groups"]:
                new_status["groups"][dest_group_name] = {
                    "members": [],
                    "attributes": group_attributes,
                }

            # Find members
            for _, entry in dns:
                # Add members
                members = [m.decode("UTF-8") for m in entry["member"]] if "member" in entry else []
                for member in members:
                    m_uid = dn2rdns(member)["uid"][0]
                    user = render_templated_string(cfg["sync"]["users"]["rename_user"], co=co, uid=m_uid)
                    new_status["groups"][dest_group_name]["members"].append(user)
                    if user not in status["groups"][dest_group_name]["members"]:
                        event_handler.add_user_to_group(dest_group_name, user, group_attributes)
        except ldap.NO_SUCH_OBJECT:
            logger.warning(f"service '{fq_co}' does not contain group '{sram_group}'")
        except:
            raise

    return new_status


def add_missing_entries_to_ldap(cfg, status, new_status):
    """
    Determine which entries in the SRAM LDAP have not been processed before.

    This is the main loop. It loops over all services that are in the SRAM LDAP
    for the service provider. For each service it is determined if it needs to
    be added to the destination LDAP. The work in determining what is defined
    in the SRAM LDAP is split into two: i) processing user data and ii)
    processing group data.

    The current state the destination LDAP should be in is tracked in
    new_status, while status is the previous known status of the destination
    LDAP."""

    event_handler = cfg.event_handler
    ldap_conn = cfg.getLDAPconnector()
    basedn = cfg.getSRAMbasedn()
    dns = ldap_conn.search_s(
        f"dc=ordered,{basedn}",
        ldap.SCOPE_ONELEVEL,
        "(&(o=*)(ObjectClass=organization))",
    )

    for _, entry in dns:
        fq_co = entry["o"][0].decode("UTF-8")
        org, co = fq_co.split(".")
        event_handler.start_of_service_processing(co)
        logger.debug(f"Processing CO: {co}")

        new_status = process_user_data(cfg, fq_co, co, status, new_status)
        new_status = process_group_data(cfg, fq_co, org, co, status, new_status)

    return new_status


def remove_graced_users(cfg, status, new_status) -> dict:
    if "groups" not in new_status:
        return new_status

    event_handler = cfg.event_handler

    for group, v in status["groups"].items():
        if "graced_users" in v:
            logger.debug(f"Checking graced users for group: {group}")
            for user, grace_until_str in v["graced_users"].items():
                grace_until = datetime.strptime(grace_until_str, "%Y-%m-%d %H:%M:%S%z")
                now = datetime.now(timezone.utc)
                if now > grace_until:
                    # The graced info for users is in status initially and needs to be
                    # copied over to new_status if it needs to be preserved. Not doing
                    # so automatically disregards this information automatically and
                    # it is the intended behaviour
                    logger.info(f"Grace time ended for user {user} in {group}")
                    group_attributes = cfg["sync"]["groups"][group]["attributes"]
                    event_handler.remove_graced_user_from_group(group, user, group_attributes)
                else:
                    if "graced_users" not in new_status["groups"][group]:
                        new_status["groups"][group]["graced_users"] = {}
                    new_status["groups"][group]["graced_users"][user] = grace_until_str

                    remaining_time = grace_until - now
                    logger.info(f"{user} from {group} has {remaining_time} left of its grace time.")
    return new_status


def remove_deleted_users_from_groups(cfg, status, new_status) -> dict:
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
                    logger.info(
                        f'User "{user}" has been removed but not deleted due to grace time. Remaining time: {remaining_time}'
                    )
                    new_status["groups"][group]["graced_users"] = {
                        user: datetime.strftime(grace_until, "%Y-%m-%d %H:%M:%S%z")
                    }
                else:
                    logger.warning(
                        f'Grace has not been defined for group "{group}" in the configuration file.'
                    )
            else:
                event_handler.remove_user_from_group(group, v["attributes"], user)

    return new_status


def remove_deleted_groups(cfg, status, new_status):
    event_handler = cfg.event_handler

    removed_groups = [group for group in status["groups"] if group not in new_status["groups"]]

    for group in removed_groups:
        t = {"groups": status["groups"][group]}
        t2 = {"groups": new_status["groups"][group]}
        t2["groups"][group]["members"] = {}

        new_status = remove_deleted_users_from_groups(cfg, t, t2)

        logger.debug(f"Removing group: '{group}'")
        event_handler.remove_group(group, status["groups"][group]["attributes"])

    return new_status


def remove_superfluous_entries_from_ldap(cfg, status, new_status):
    """
    Remove entries in the destination LDAP based on the difference between
    status and new_status.
    """

    new_status = remove_deleted_groups(cfg, status, new_status)
    new_status = remove_graced_users(cfg, status, new_status)
    new_status = remove_deleted_users_from_groups(cfg, status, new_status)

    return new_status


def get_event_handler(cfg):
    event_name = cfg["sync"]["event_handler"]["name"]
    event_module = importlib.import_module(f"SRAMsync.{event_name}")
    event_class = getattr(event_module, event_name)

    handler_cfg = {}
    if "config" in cfg["sync"]["event_handler"]:
        handler_cfg = cfg["sync"]["event_handler"]["config"]

    handler_cfg.update({"status_filename": cfg["status_filename"]})

    if "provisional_status_filename" in cfg:
        handler_cfg.update({"provisional_status_filename": cfg["provisional_status_filename"]})

    event_handler = event_class(cfg["service"], handler_cfg, ["sync", "event_handler", "config"])

    return event_handler


def keep_new_status(cfg, new_status):
    if "provisional_status_filename" in cfg:
        filename = cfg["provisional_status_filename"]
    else:
        filename = cfg["status_filename"]

    filename = render_templated_string(filename, service=cfg["service"])

    with open(filename, "w") as status_file:
        json.dump(new_status, status_file, indent=2)

    logger.info(f"new status file has been written to: {filename}")


def get_configurations(path):
    if os.path.isdir(path):
        paths = os.listdir(path)
        paths = sorted([os.path.join(path, x) for x in paths if x.endswith(("yaml", "yml"))])
    else:
        paths = [path]

    return paths


@click.command(context_settings=click_ctx_settings)
@click.option("-d", "--debug", is_flag=True, default=False, help="Set log level to DEBUG")
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Set log level to INFO or DEBUG, depending depending on the count",
)
@click.version_option()
@click_logging.simple_verbosity_option(logger, "--log-level", "-l", **click_logging_options)
@click.argument("configuration", type=click.Path(exists=True, dir_okay=True))
def cli(configuration, debug, verbose):
    """
    Synchronisation between the SRAM LDAP and the destination LDAP

    sync_with_sram takes an configuration file which describes a source LDAP
    with which the destination LDAP must be synchronized. This configuration
    file also describes which groups need to be considered for synchronisation.

    During a synchronisation run, a status is kept. It reflects the current
    state of what has been done in order to synchronize the destination LDAP.
    However, the actual actions to make changes to the destination LDAP are
    diverted to a generated script file. Once sync_with_sram has finished
    running, this resulting script file must be executed in order to finish the
    syncing process.

    The generated status file is written to disk to keep this history. Upon a
    next run, the previous known status is read and used to determine if
    additional actions are required to keep the destination LDAP in sync the
    SRAM. Thus the status is used to prevent adding things to the destination
    LDAP when that already has happened.

    CONFIGURATION: Path to a configuration file. OUTPUT: Path of the resulting
    script.
    """

    clean_exit = False

    if debug:
        logging.getLogger("SRAMsync").setLevel(logging.DEBUG)

    if verbose > 0:
        if verbose > 2:
            logger.warning("verbose option supports two level only. Additional levels are ignored.")
            verbose = 2
        verbose_logging = ["INFO", "DEBUG"]
        logging.getLogger("SRAMsync").setLevel(verbose_logging[verbose - 1])

    configurations = get_configurations(configuration)

    try:
        logger.info(f"Started syncing with SRAM")

        for configuration in configurations:
            new_status = {"users": {}, "groups": {}}
            cfg = Config(configuration)

            event_handler = get_event_handler(cfg)
            cfg.setEventHandler(event_handler)

            ldap_conn = init_ldap(cfg["sram"], cfg["service"])
            cfg.setLDAPconnector(ldap_conn)
            status = get_previous_status(cfg)
            new_status = add_missing_entries_to_ldap(cfg, status, new_status)
            new_status = remove_superfluous_entries_from_ldap(cfg, status, new_status)

            event_handler.finalize()

            keep_new_status(cfg, new_status)
            logger.info("Finished syncing with SRAM")
            clean_exit = True
    except IOError as e:
        logger.error(e)
    except jsonschema.exceptions.ValidationError as e:
        if isinstance(e, ConfigValidationError):
            path = e.path
            path.extend(e.exception.relative_path)
            e = e.exception
        else:
            path = e.relative_path

        logger.error(f"Syntax error in configuration file {configuration} at:")
        indent_level = 0
        for path_element in path:
            logger.error(" " * indent_level * 2 + f"{path_element}:")
            indent_level = indent_level + 1
        logger.error(" " * indent_level * 2 + e.message)

        logger.debug(e)
    except PasswordNotFound as e:
        logger.error(e.msg)
    except ldap.NO_SUCH_OBJECT as e:
        if "desc" in e.args[0]:
            logger.error(e.args[0]["desc"])
    except ldap.INVALID_CREDENTIALS:
        logger.error(
            "Invalid credentials. Please check your configuration file or set SRAM_LDAP_PASSWD correctly."
        )
    except ldap.SERVER_DOWN as e:
        if "desc" in e.args[0]:
            logger.error(e.args[0]["desc"])
    except ModuleNotFoundError as e:
        logger.error(f"{e}. Please check your config file.")
    except MultipleLoginGroups:
        logger.error("Multiple login groups have been defined in the config file. Only one is allowed.")

    if not clean_exit:
        sys.exit(1)
