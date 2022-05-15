"""
sync-with-sram is a command line untility to help synchronize a local system,
e.g. LDAP, with the LDAP provided by SRAM. Keep in mind though that the SRAM
LDAP provides attributes only and that it does not provide posix account and
groups.

sync-with-sram consists in essence out of two parts: 1) a main loop that
iterates over the entries and retrieves attrbutes from the SRAM LDAP, 2) an
event like system that acts on detected changes between the current state of
the SRAM LDAP and the current state of the destination system.

This event system is modular and what sync-with-sram really does depends on
what module is configured. It could bea sending a simple email message, or it
could be interacting with the destination system.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import List

import click
import click_logging
import jsonschema.exceptions
import ldap
from ldap import ldapobject
from ldap.dn import str2dn

from SRAMsync.common import get_attribute_from_entry, render_templated_string
from SRAMsync.config import Config
from SRAMsync.sramlogger import logger

#  By default click does not offer the short '-h' option.
click_ctx_settings = dict(help_option_names=["-h", "--help"])
re_grace_period = re.compile(
    "^grace_period=(?:(?:[0-9]+[d|m|H|M|s]?)$|(?:[0-9]+:)?(?:2[0-3]|[01]?[0-9]):(?:[0-5][0-9])(?::[0-5][0-9])?)$"
)

#  Adjust some of the defaults of click_logging.
click_logging_options = {
    "default": "WARNING",
    "metavar": "level",
    "help": "level should be one of: CRITICAL, ERROR, WARNING, INFO or DEBUG.",
}


class ConfigValidationError(jsonschema.exceptions.ValidationError):
    """Exception in case the supplied configuration file contains errors"""

    def __init__(self, exception, path):
        super().__init__(exception, path)
        self.path = path
        self.exception = exception


class MultipleLoginGroups(Exception):
    """Exception in case multiple login groups are found."""


class PasswordNotFound(Exception):
    """Exception is case no password has been found."""

    def __init__(self, msg):
        super().__init__(msg)
        self.msg = msg


def dn_to_rdns(dn: str) -> dict:
    """
    Convert the given dn string representation info into a dictionary, where
    each key value pair is an rdn.
    """

    rdns = {}
    rdn_components = str2dn(dn)
    for rdn in rdn_components:
        attribute, value, _ = rdn[0]
        rdns.setdefault(attribute, []).append(value)
    return rdns


def get_ldap_passwd(config: dict, secrets: dict, service: str) -> str:
    """
    Get the SRAM LDAP password.

    The configuration file could contain the password, or a path to a password
    file. If either is used, retrieve the password through that method. If
    neither is used or if the environment variable SRAM_DAP_PASSWD is set, use
    that value instead.
    """

    if "SRAM_LDAP_PASSWD" in os.environ:
        return os.environ["SRAM_LDAP_PASSWD"]

    if "passwd" in config:
        return config["passwd"]

    try:
        if config["passwd_from_secrets"] is True:
            return secrets["sram-ldap"][service]

        logger.error(
            "In the config file passwd_from_secrets is set to false and no environment "
            "variable or no secrets file has been set."
        )
    except KeyError:
        pass

    raise PasswordNotFound("SRAM LDAP password not found. Check your configuration or set SRAM_LDAP_PASSWD.")


def init_ldap(config: dict, secrets: dict, service: str) -> ldapobject.LDAPObject:
    """
    Initialization and binding an LDAP connection.
    """
    logger.debug(f"LDAP: connecting to: {config['uri']}")
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)  # type: ignore pylint: disable=E1101
    ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)  # type: ignore, pylint: disable=E1101
    ldap_conn = ldap.initialize(config["uri"])
    passwd = get_ldap_passwd(config, secrets, service)
    ldap_conn.simple_bind_s(config["binddn"], passwd)
    logger.debug("LDAP: connected")

    return ldap_conn


def get_previous_status(cfg: Config) -> dict:
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
    except FileNotFoundError:
        pass

    return status


def is_user_eligible(uid: str, login_users: List[str], entry: dict) -> bool:
    """
    Check if the user (uid) is eligible for using the service. There are two
    ways to determine this. i) if the users is found to be part of the
    login_users. ii) if the voPersonStatus is set for the user.

    If no login_users are defined nor is the voPersonStatus used, the user is
    always eligible.
    """
    if login_users and uid not in login_users:
        return False

    if "voPersonStatus" in entry:
        vo_person_status = get_attribute_from_entry(entry, "voPersonStatus")
        if vo_person_status != "active":
            return False

    return True


def get_login_users(cfg: Config, service: str, co: str) -> List[str]:
    """
    Check if there is at least one and not more than one group that controls
    which users are allowed to login. If there are none, it's okay to use all
    known users from the reserved '@all` group.
    """
    ldap_conn = cfg.get_ldap_connector()

    login_groups = [group for group, v in cfg["sync"]["groups"].items() if "login_users" in v["attributes"]]
    login_users = []
    number_of_groups = len(login_groups)

    if number_of_groups > 1:
        raise MultipleLoginGroups()

    if number_of_groups == 0:
        login_groups = ["@all"]

    group = login_groups[0]
    try:
        dns = ldap_conn.search_s(
            f"ou=Groups,o={service},dc=ordered,{cfg.get_sram_basedn()}",
            ldap.SCOPE_ONELEVEL,  # type: ignore: pylint: disable=E1101
            f"(cn={group})",
        )
        for _, entry in dns:  # type: ignore
            if "member" in entry:
                for member in entry["member"]:
                    uid = dn_to_rdns(member)["uid"][0]
                    login_users.append(uid)
    except ldap.NO_SUCH_OBJECT:  # type: ignore: pylint: disable=E1101
        logger.warning(f"login group '{group}' has been defined but could not be found for CO '{co}'.")

    return login_users


def process_user_data(cfg: Config, fq_co: str, co: str, status: dict, new_status: dict) -> dict:
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

    ldap_conn = cfg.get_ldap_connector()
    event_handler = cfg.event_handler_proxy
    group = f"{cfg['service']}_login"

    login_users = get_login_users(cfg, fq_co, co)

    try:
        dns = ldap_conn.search_s(
            f"ou=People,o={fq_co},dc=ordered,{cfg.get_sram_basedn()}",
            ldap.SCOPE_ONELEVEL,  # type: ignore pylint: disable=E1101
            "(objectClass=person)",
        )

        for _, entry in dns:  # type: ignore
            uid = get_attribute_from_entry(entry, "uid")
            if is_user_eligible(uid, login_users, entry):
                givenname = get_attribute_from_entry(entry, "givenName")
                sn = get_attribute_from_entry(entry, "sn")
                user = render_templated_string(cfg["sync"]["users"]["rename_user"], co=co, uid=uid)
                mail = get_attribute_from_entry(entry, "mail")

                new_status["users"][user] = {"sram": {"CO": co}}
                if user not in status["users"]:
                    logger.debug(f"  Found new user: {user}")
                    event_handler.add_new_user(co, group, givenname, sn, user, mail)

                if "sshPublicKey" in entry:
                    raw_ssh_public_keys = entry["sshPublicKey"]
                    ssh_public_keys = set([raw_ssh_public_keys[0].decode("UTF-8").rstrip()])
                    for key in raw_ssh_public_keys[1:]:
                        ssh_public_keys = ssh_public_keys | {key.decode("UTF-8").rstrip()}

                    known_ssh_public_keys = set()
                    if user in status["users"] and "sshPublicKey" in status["users"][user]:
                        known_ssh_public_keys = set(status["users"][user]["sshPublicKey"])
                    new_status["users"][user]["sshPublicKey"] = list(ssh_public_keys)

                    new_ssh_public_keys = ssh_public_keys - known_ssh_public_keys
                    dropped_ssh_public_leys = known_ssh_public_keys - ssh_public_keys

                    for key in new_ssh_public_keys:
                        logger.debug(f"    Adding public SSH key: {key[:50]}…")
                        event_handler.add_public_ssh_key(co, user, key)

                    for key in dropped_ssh_public_leys:
                        logger.debug(f"    Removing public SSH key: {key[:50]}…")
                        event_handler.delete_public_ssh_key(co, user, key)

    except ldap.NO_SUCH_OBJECT:  # type: ignore pylint: disable=E1101
        logger.error("The basedn does not exists.")

    return new_status


def process_group_data(cfg: Config, fq_co: str, org: str, co: str, status: dict, new_status: dict) -> dict:
    """
    Process the CO group data as found in SRAM for the service. Only those
    groups that are defined in the configuration file are processed.

    Collect the necessary information from SRAM such that shell commands can be
    generated that call for the respective sara_usertools commands with the
    collected information.

    The provided status is used to determine whether or not a user has already
    been added to the group in a previous run.

    While looping over all groups, a new_status is maintained to reflect the to
    be situation of the destination LDAP. This to be situation will be achieved
    after a successful run of the resulting script.
    """

    event_handler = cfg.event_handler_proxy
    ldap_conn = cfg.get_ldap_connector()
    service = cfg["service"]  # service might be accessed indirectly

    for sram_group, value in cfg["sync"]["groups"].items():
        group_attributes = value["attributes"]
        dest_group_name = value["destination"]

        if "ignore" in group_attributes:
            continue

        try:
            basedn = cfg.get_sram_basedn()
            dns = ldap_conn.search_s(
                f"cn={sram_group},ou=Groups,o={fq_co},dc=ordered,{basedn}",
                ldap.SCOPE_BASE,  # type: ignore pylint: disable=E1101
                "(objectClass=groupOfMembers)",
            )
            # The dest_group_name could contain an org reference
            dest_group_name = render_templated_string(dest_group_name, service=service, org=org, co=co)

            # Create groups
            if dest_group_name not in status["groups"]:
                logger.debug(f"  Adding group: {dest_group_name}")
                event_handler.add_new_group(co, dest_group_name, group_attributes)

            if dest_group_name not in new_status["groups"]:
                new_status["groups"][dest_group_name] = {
                    "members": [],
                    "attributes": group_attributes,
                    "sram": {
                        "CO": co,
                        "sram-group": sram_group,
                    },
                }

            # Find members
            for _, entry in dns:  # type: ignore
                # Add members
                members = [m.decode("UTF-8") for m in entry["member"]] if "member" in entry else []
                for member in members:
                    m_uid = dn_to_rdns(member)["uid"][0]
                    user = render_templated_string(cfg["sync"]["users"]["rename_user"], co=co, uid=m_uid)
                    new_status["groups"][dest_group_name]["members"].append(user)
                    if dest_group_name in status["groups"]:
                        if user not in status["groups"][dest_group_name]["members"]:
                            event_handler.add_user_to_group(co, dest_group_name, group_attributes, user)
        except ldap.NO_SUCH_OBJECT:  # type: ignore pylint: disable=E1101
            logger.warning(f"service '{fq_co}' does not contain group '{sram_group}'")

    return new_status


def add_missing_entries_to_ldap(cfg: Config, status: dict, new_status: dict) -> dict:
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

    event_handler = cfg.event_handler_proxy
    ldap_conn = cfg.get_ldap_connector()
    basedn = cfg.get_sram_basedn()
    dns = ldap_conn.search_s(
        f"dc=ordered,{basedn}",
        ldap.SCOPE_ONELEVEL,  # type: ignore pylint: disable=E1101
        "(&(o=*)(ObjectClass=organization))",
    )

    for _, entry in dns:  # type: ignore
        fq_co = get_attribute_from_entry(entry, "o")
        org, co = fq_co.split(".")
        event_handler.start_of_co_processing(co)
        logger.debug(f"Processing CO: {co}")

        new_status = process_user_data(cfg, fq_co, co, status, new_status)
        new_status = process_group_data(cfg, fq_co, org, co, status, new_status)

    return new_status


def remove_graced_users(cfg: Config, status: dict, new_status: dict) -> dict:
    """Remove users that have passed the grace period."""

    if "groups" not in new_status:
        return new_status

    event_handler = cfg.event_handler_proxy

    for group, group_attributes in status["groups"].items():
        if "graced_users" in group_attributes:
            logger.debug(f"Checking graced users for group: {group}")
            for user, grace_until_str in group_attributes["graced_users"].items():
                grace_until = datetime.strptime(grace_until_str, "%Y-%m-%d %H:%M:%S%z")
                now = datetime.now(timezone.utc)
                co = status["groups"][group]["sram"]["CO"]
                if now > grace_until:
                    # The graced info for users is in status initially and needs to be
                    # copied over to new_status if it needs to be preserved. Not doing
                    # so automatically disregards this information automatically and
                    # it is the intended behaviour
                    logger.info(f"Grace time ended for user {user} in {group}")
                    group_attributes = cfg["sync"]["groups"][group]["attributes"]
                    event_handler.remove_graced_user_from_group(co, group, group_attributes, user)
                else:
                    if "graced_users" not in new_status["groups"][group]:
                        new_status["groups"][group]["graced_users"] = {}
                    new_status["groups"][group]["graced_users"][user] = grace_until_str

                    remaining_time = grace_until - now
                    logger.info(f"{user} from {group} has {remaining_time} left of its grace time.")
    return new_status


def remove_deleted_users_from_groups(cfg: Config, status: dict, new_status: dict) -> dict:
    """
    Determine based on the (old) status and new_status which users are to be removed.
    """

    event_handler = cfg.event_handler_proxy

    for group, group_values in status["groups"].items():
        removed_users = [
            user for user in group_values["members"] if user not in new_status["groups"][group]["members"]
        ]
        co = group_values["sram"]["CO"]

        for user in removed_users:
            if "grace_period" in group_values["attributes"]:
                if "grace" in cfg["sync"] and group in cfg["sync"]["grace"]:
                    grace_until = datetime.now(timezone.utc) + timedelta(new_status["grace"][group])
                    remaining_time = grace_until - datetime.now(timezone.utc)
                    logger.info(
                        f"User '{user}' has been removed but not deleted due to grace time. "
                        f"Remaining time: {remaining_time}"
                    )
                    event_handler.start_grace_period_for_user(
                        co, group, group_values["attributes"], user, remaining_time
                    )
                    new_status["groups"][group]["graced_users"] = {
                        user: datetime.strftime(grace_until, "%Y-%m-%d %H:%M:%S%z")
                    }
                else:
                    logger.warning(
                        f'Grace has not been defined for group "{group}" in the configuration file.'
                    )
            else:
                event_handler.remove_user_from_group(co, group, group_values["attributes"], user)

    return new_status


def remove_deleted_groups(cfg: Config, status: dict, new_status: dict) -> dict:
    """
    Determine based on (old) status and new_status which groups are to
    be removed. If any of those groups contain members, remove those members
    first from the group.
    """

    event_handler = cfg.event_handler_proxy

    removed_groups = [group for group in status["groups"] if group not in new_status["groups"]]

    for group in removed_groups:
        co = status["groups"][group]["sram"]["CO"]
        old_group_status = {"groups": status["groups"][group]}
        new_group_status = {"groups": new_status["groups"][group]}
        new_group_status["groups"][group]["members"] = {}

        new_status = remove_deleted_users_from_groups(cfg, old_group_status, new_group_status)

        logger.debug(f"Removing group: '{group}'")
        event_handler.remove_group(co, group, status["groups"][group]["attributes"])

    return new_status


def remove_superfluous_entries_from_ldap(cfg: Config, status: dict, new_status: dict) -> dict:
    """
    Remove entries in the destination LDAP based on the difference between
    status and new_status.
    """

    new_status = remove_deleted_groups(cfg, status, new_status)
    new_status = remove_graced_users(cfg, status, new_status)
    new_status = remove_deleted_users_from_groups(cfg, status, new_status)

    return new_status


def keep_new_status(cfg: Config, new_status: dict) -> None:
    """
    Write the new status to the defined status_filename or
    provisional_status_filename depending on the configuration.
    """

    if "provisional_status_filename" in cfg:
        filename = cfg["provisional_status_filename"]
    else:
        filename = cfg["status_filename"]

    filename = render_templated_string(filename, service=cfg["service"])

    with open(filename, "w") as status_file:
        json.dump(new_status, status_file, indent=2)

    logger.info(f"new status file has been written to: {filename}")


def get_configuration_paths(path: str) -> List[str]:
    """
    Return an array containing paths to configurations in case the provided
    path was a directory, or a single path if the path was a file.
    """

    if os.path.isdir(path):
        paths = os.listdir(path)
        paths = sorted([os.path.join(path, x) for x in paths if x.endswith(("yaml", "yml"))])
    else:
        paths = [path]

    return paths


def show_configuration_error(
    configuration_path: str, path: dict, exception: jsonschema.exceptions.ValidationError
) -> None:
    """Display the path in the configuration where the error occured."""
    logger.error(f"Syntax error in configuration file {configuration_path} at:")

    indent_level = 0
    for path_element in path:
        logger.error(" " * indent_level * 2 + f"{path_element}:")
        indent_level = indent_level + 1
    logger.error(" " * indent_level * 2 + exception.message)


@click.command(context_settings=click_ctx_settings)
@click.option(
    "-e",
    "--eventhandler-args",
    "raw_eventhandler_args",
    help="Add additional arguments for EventHandler classes.",
)
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
def cli(configuration, debug, verbose, raw_eventhandler_args):
    """
    Synchronisation between the SRAM LDAP and the destination LDAP

    sync_with_sram takes a configuration file or path containing multiple files
    which describe one or more source LDAPs with which the destination LDAP
    must be synchronized. This configuration file also describes which groups
    need to be considered for synchronisation.

    During a synchronisation run, a status is kept. It reflects the current
    state of what has been done in order to synchronize the destination LDAP.
    However, the actual actions to make changes to the destination LDAP are
    diverted to a generated script file. Once sync_with_sram has finished
    running, this resulting script file must be executed in order to finish the
    syncing process.

    The generated status file is written to disk to keep this history. Upon a
    next run, the previous known status is read and used to determine if
    additional actions are required to keep the destination LDAP in sync with
    SRAM. Thus the status is used to prevent adding things to the destination
    LDAP when that already has happened.

    CONFIGURATION: Path to a configuration file, or directory containing
    configuration files.
    """

    clean_exit = False
    configuration_path = ""

    eventhandler_args = {}
    if raw_eventhandler_args:
        for argument in raw_eventhandler_args.split(","):
            if "=" in argument:
                key, value = argument.split("=", 1)
            else:
                key = argument
                value = None
            eventhandler_args[key] = value

    if debug:
        logging.getLogger("SRAMsync").setLevel(logging.DEBUG)

    if verbose > 0:
        if verbose > 2:
            logger.warning("verbose option supports two levels only. Additional levels are ignored.")
            verbose = 2
        verbose_logging = ["INFO", "DEBUG"]
        logging.getLogger("SRAMsync").setLevel(verbose_logging[verbose - 1])

    try:
        logger.info("Started syncing with SRAM")

        configuration_paths = get_configuration_paths(configuration)

        for configuration_path in configuration_paths:
            logger.info(f"Handling configuration: {configuration_path}")

            new_status = {"users": {}, "groups": {}}
            cfg = Config(configuration_path, **dict(eventhandler_args))

            ldap_conn = init_ldap(cfg["sram"], cfg.secrets, cfg["service"])
            cfg.set_set_ldap_connector(ldap_conn)
            status = get_previous_status(cfg)
            new_status = add_missing_entries_to_ldap(cfg, status, new_status)
            new_status = remove_superfluous_entries_from_ldap(cfg, status, new_status)

            cfg.event_handler_proxy.finalize()

            keep_new_status(cfg, new_status)

        logger.info("Finished syncing with SRAM")
        clean_exit = True
    except IOError as e:
        logger.error(e)
    except ConfigValidationError as e:
        path = e.path
        path.extend(e.exception.relative_path)
        show_configuration_error(configuration_path, path, e)
        logger.debug(e.exception)
    except jsonschema.exceptions.ValidationError as e:
        path = e.relative_path  # type: ignore
        show_configuration_error(configuration_path, path, e)
        logger.debug(e)
    except PasswordNotFound as e:
        logger.error(e.msg)
    except ldap.NO_SUCH_OBJECT as e:  # type: ignore pylint: disable=E1101
        if "desc" in e.args[0]:
            logger.error(e.args[0]["desc"])
    except ldap.INVALID_CREDENTIALS:  # type: ignore pylint: disable=E1101
        logger.error(
            "Invalid credentials. Please check your configuration file or set SRAM_LDAP_PASSWD correctly."
        )
    except ldap.SERVER_DOWN as e:  # type: ignore pylint: disable=E1101
        if "desc" in e.args[0]:
            logger.error(e.args[0]["desc"])
    except ModuleNotFoundError as e:
        logger.error(f"{e}. Please check your config file.")
    except MultipleLoginGroups:
        logger.error("Multiple login groups have been defined in the config file. Only one is allowed.")
    except ValueError as e:
        logger.error(e)

    if not clean_exit:
        sys.exit(1)
