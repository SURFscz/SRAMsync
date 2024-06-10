"""
sync-with-sram is a command line untility to help synchronize a local system,
e.g. LDAP, with the LDAP provided by SRAM. Keep in mind though that the SRAM
LDAP provides attributes only and that it does not provide posix account and
groups.

sync-with-sram consists in essence out of two parts: 1) a main loop that
iterates over the entries and retrieves attributes from the SRAM LDAP, 2) an
event like system that acts on detected changes between the current state of
the SRAM LDAP and the current state of the destination system.

This event system is modular and what sync-with-sram really does depends on
what module is configured. It could bea sending a simple email message, or it
could be interacting with the destination system.
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import cast

import click
import click_logging
import jsonschema.exceptions
import ldap
from ldap import ldapobject
from ldap.dn import str2dn  # type: ignore

from SRAMsync.common import (
    TemplateError,
    get_attribute_from_entry,
    render_templated_string,
    render_templated_string_list,
)
from SRAMsync.config import Config, ConfigurationError
from SRAMsync.sramlogger import logger
from SRAMsync.state import NoGracePeriodForGroupError, UnkownGroup
from SRAMsync.typing import DNs, StateFile

#  By default click does not offer the short '-h' option.
click_ctx_settings = dict(help_option_names=["-h", "--help"])

#  Adjust some of the defaults of click_logging.
click_logging_options = {
    "default": "WARNING",
    "metavar": "level",
    "help": "level should be one of: CRITICAL, ERROR, WARNING, INFO or DEBUG.",
}


class ConfigValidationError(jsonschema.exceptions.ValidationError):
    """Exception in case the supplied configuration file contains errors"""

    def __init__(self, exception: jsonschema.exceptions.ValidationError, path: list[str]):
        super().__init__(str(exception))
        self.my_path = path
        self.exception = exception


class MissingUidInRenameUser(Exception):
    """Exception in case the {uid} tag is missing from rename_user."""

    def __init__(self, msg: str):
        """Init."""
        super().__init__(msg)
        self.msg = msg


class MultipleLoginGroups(Exception):
    """Exception in case multiple login groups are found."""


class PasswordNotFound(Exception):
    """Exception is case no password has been found."""

    def __init__(self, msg: str):
        """Init."""
        super().__init__(msg)
        self.msg = msg


def dn_to_rdns(dn: str) -> dict[str, list[str]]:
    """
    Convert the given dn string representation info into a dictionary, where
    each key value pair is an rdn.
    """

    rdns = {}
    rdn_components = cast(list[tuple[str, str, int]], str2dn(dn))
    for rdn in rdn_components:
        attribute, value, _ = rdn[0]
        rdns.setdefault(attribute, []).append(value)  # type: ignore
    return cast(dict[str, list[str]], rdns)


def get_ldap_passwd(config: dict[str, str], secrets: dict[str, dict[str, str]], service: str) -> str:
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


def init_ldap(
    config: dict[str, str], secrets: dict[str, dict[str, str]], service: str
) -> ldapobject.LDAPObject:
    """
    Initialization and binding an LDAP connection.
    """
    logger.debug("LDAP: connecting to: %s", config["uri"])
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)  # type: ignore
    ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)  # type: ignore
    ldap_conn = cast(ldapobject.LDAPObject, ldap.initialize(config["uri"]))  # type: ignore
    passwd = get_ldap_passwd(config, secrets, service)
    ldap_conn.simple_bind_s(config["binddn"], passwd)  # type: ignore
    logger.debug("LDAP: connected")

    return ldap_conn


def get_previous_status(cfg: Config) -> StateFile:
    """
    Get the saved status from disk if it exits. Return an empty status otherwise.
    """
    status: StateFile = {"users": {}, "groups": {}}

    if "provisional_status_filename" in cfg and os.path.isfile(cfg["provisional_status_filename"]):
        logger.warning("Found unexpected provisional status file: %s", cfg["provisional_status_filename"])
        logger.warning("Possible reason is that the generated script has not been run yet.")
        logger.warning("It is okay to continue this sync and generate a new up-to-date script.")

    filename = render_templated_string(cfg["status_filename"], service=cfg["service"])
    try:
        with open(filename, encoding="utf8") as json_file:
            status = json.load(json_file)
    except FileNotFoundError:
        pass

    return status


def is_user_eligible(cfg: Config, entry: dict, user: str) -> bool:
    """
    Check if the user (uid) is eligible for using the service. There are two
    ways to determine this. i) if the users is found to be part of the
    login_users. ii) if the voPersonStatus is set for the user.

    A user is eligible if all of the following is true:
      - voPersonPolicyAgreement is defined
      - if the user is in the login_users or no login_users are defined
      - voPersonStatus defined and set to 'active'
    """

    uid = get_attribute_from_entry(entry, "uid")

    if "aup_enforcement" in cfg["sync"]["users"] and cfg["sync"]["users"]["aup_enforcement"]:
        a = [k for k in entry.keys() if "voPersonPolicyAgreement" in k]
        if not a:
            logger.warning("Igoring %s. AUP attribute (voPersonPolicyAgreement) is missing.", uid)
            return False

        timestamps = [k.split(";")[1].split("-")[1] for k in a]
        timestamps.sort(reverse=True)

        for timestamp in timestamps:
            logger.debug("User %s accepted policies on: %s", user, datetime.fromtimestamp(int(timestamp)))

    if "voPersonStatus" in entry:
        vo_person_status = get_attribute_from_entry(entry, "voPersonStatus")
        if vo_person_status != "active":
            return False

    return True


def render_user_name(cfg: Config, org: str, co: str, group: str, uid: str) -> str:
    """
    Render the new user name base on the template as defined by the configuration file.
    """
    service = cfg["service"]
    template = ""

    if isinstance(cfg["sync"]["users"]["rename_user"], str):
        template = cfg["sync"]["users"]["rename_user"]
    else:
        try:
            template = cfg["sync"]["users"]["rename_user"]["groups"][group]
        except KeyError:
            try:
                template = cfg["sync"]["users"]["rename_user"]["default"]
            except KeyError:
                logger.error(
                    "Renaming for co %s failed, because there is not specific rule that co, "
                    "nor is there a default defined.",
                    co,
                )
                sys.exit(-1)

    if "{uid}" not in template:
        raise MissingUidInRenameUser("'{uid}' is missing from the 'rename_user' template.")

    user_name = render_templated_string(template, service=service, org=org, co=co, uid=uid)

    return user_name


def get_login_groups_and_users(cfg: Config, service: str, co: str) -> dict[str, list[str]]:
    """
    Check if there is at least one and not more than one group that controls
    which users are allowed to login. If there are none, it's okay to use all
    known users from the reserved '@all` group.
    """

    ldap_conn = cfg.get_ldap_connector()

    login_groups_and_users = {}
    if "groups" in cfg["sync"]:
        login_groups_and_users = {
            group: [] for group, v in cfg["sync"]["groups"].items() if "login_users" in v["attributes"]
        }

    if not login_groups_and_users:
        login_groups_and_users = cfg["sync"]["groups"]["@all"]

    for group in login_groups_and_users:
        try:
            dns = ldap_conn.search_s(
                f"ou=Groups,o={service},dc=ordered,{cfg.get_sram_basedn()}",
                ldap.SCOPE_ONELEVEL,  # type: ignore pylint: disable=E1101
                f"(cn={group})",
            )
            for _, entry in dns:  # type: ignore
                if "member" in entry:
                    for member in entry["member"]:
                        uid = dn_to_rdns(member)["uid"][0]
                        login_groups_and_users[group].append(uid)
        except ldap.NO_SUCH_OBJECT:  # type: ignore pylint: disable=E1101
            logger.warning("login group '{group}' has been defined but could not be found for CO '%s'.", co)

    return login_groups_and_users


def handle_public_ssh_keys(cfg: Config, co: str, user: str, entry: dict[str, list[bytes]]) -> None:
    """
    Determine if a public SSH had been added or deleted and generate the
    appropriate event if necessary.
    """

    if "sshPublicKey" in entry:
        raw_ssh_public_keys = entry["sshPublicKey"]
        current_ssh_public_keys = set([raw_ssh_public_keys[0].decode("UTF-8").rstrip()])
        for key in raw_ssh_public_keys[1:]:
            current_ssh_public_keys = current_ssh_public_keys | {key.decode("UTF-8").rstrip()}

        known_ssh_public_keys = cfg.state.get_known_user_public_ssh_keys(user)
        cfg.state.set_user_public_ssh_keys(user, current_ssh_public_keys)

        new_ssh_public_keys = current_ssh_public_keys - known_ssh_public_keys
        dropped_ssh_public_leys = known_ssh_public_keys - current_ssh_public_keys

        event_handler = cfg.event_handler_proxy
        for key in new_ssh_public_keys:
            logger.debug("    Adding public SSH key: %s…", key[:50])
            event_handler.add_public_ssh_key(co, user, key)

        for key in dropped_ssh_public_leys:
            logger.debug("    Removing public SSH key: %s…", key[:50])
            event_handler.delete_public_ssh_key(co, user, key)


def process_co_attributes(cfg: Config, fq_co: str, org: str, co: str) -> None:
    """
    Each CO had a number of attributes. Let the event handler deal with
    them.
    """
    ldap_conn = cfg.get_ldap_connector()

    dn = f"o={fq_co},dc=ordered,{cfg.get_sram_basedn()}"

    dns = ldap_conn.search_s(  # type: ignore
        dn,
        ldap.SCOPE_BASE,  # type: ignore
        f"(o={fq_co})",
    )

    if dns:
        number_of_matching_dns = len(dns)  # type: ignore
        if number_of_matching_dns != 1:
            raise ValueError("Expected one element for %s, found %s", dn, number_of_matching_dns)
        try:
            attributes = cast(dict[str, str], dns[0][1])
            event_handler = cfg.event_handler_proxy
            event_handler.process_co_attributes(attributes, org, co)
        except KeyError:
            logger.warn("UUID for CO %s of org %s not found.", co, org)
    else:
        raise ValueError("Failed getting attributes from: %s", dn)


def process_user_data(cfg: Config, fq_co: str, org: str, co: str) -> None:
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

    dn = ""
    ldap_conn = cfg.get_ldap_connector()
    login_groups = get_login_groups_and_users(cfg, fq_co, co)
    new_users: list[str] = []

    try:
        for login_group, login_users in login_groups.items():
            for user in login_users:
                dn = f"uid={user},ou=People,o={fq_co},dc=ordered,{cfg.get_sram_basedn()}"
                dns: DNs = ldap_conn.search_s(  # type: ignore
                    dn,
                    ldap.SCOPE_BASE,  # type: ignore pylint: disable=E1101
                    "(objectClass=person)",
                )

                entry: dict[str, list[bytes]] = dns[0][1]  # type: ignore
                if is_user_eligible(cfg, entry, user):
                    login_dest_group_names = render_templated_string_list(
                        cfg["sync"]["groups"][login_group]["destination"],
                        service=cfg["service"],
                        org=org,
                        co=co,
                        sram_group=login_group,
                    )
                    uid: str = get_attribute_from_entry(entry, attribute="uid")  # type: ignore

                    dest_user_name = render_user_name(cfg, org=org, co=co, group=login_group, uid=uid)

                    cfg.state.add_user(dest_user_name, co)

                    if dest_user_name in new_users:
                        logger.error(
                            "User %s has already been added. Possible error in configuration.",
                            dest_user_name,
                        )
                        sys.exit(1)

                    if not cfg.state.is_known_user(dest_user_name):
                        group_attributes = render_templated_string_list(
                            cfg["sync"]["groups"][login_group]["attributes"],
                            service=cfg["service"],
                            org=org,
                            co=co,
                            sram_group=login_group,
                        )
                        logger.debug("  Found new user: %s", dest_user_name)
                        event_handler = cfg.event_handler_proxy

                        event_handler.add_new_user(
                            entry,  # type: ignore
                            org=org,
                            co=co,
                            groups=login_dest_group_names,
                            group_attributes=group_attributes,
                            user=dest_user_name,
                        )
                        new_users.append(dest_user_name)

                    handle_public_ssh_keys(cfg, co, dest_user_name, entry)  # type: ignore
    except ldap.NO_SUCH_OBJECT as e:  # type: ignore
        logger.error(
            "Could not find user '%s'. Only This basedn '%s' exists. Trying to match: %s",
            user,  # type: ignore
            e.args[0]["matched"],  # type: ignore
            dn,
        )


def process_group_data(cfg: Config, fq_co: str, org: str, co: str) -> None:
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

    if "groups" not in cfg["sync"]:
        return

    event_handler = cfg.event_handler_proxy
    ldap_conn = cfg.get_ldap_connector()
    service = cfg["service"]

    # for sram_group, value in non_login_groups.items():
    for sram_group, value in cfg["sync"]["groups"].items():
        if sram_group == "@all" and not value["destination"]:
            # Do not continue in case the `@all` group has been inserted
            # in the, in memory, config file. In which case the destination
            # is empty. Had the `@all` group been added to the config file
            # by the user, the destination would have been set.
            continue

        group_attributes = render_templated_string_list(
            value["attributes"], service=service, org=org, co=co, sram_group=sram_group
        )
        dest_group_names = render_templated_string_list(
            value["destination"], service=service, org=org, co=co, sram_group=sram_group
        )

        try:
            basedn = cfg.get_sram_basedn()
            dns: DNs = ldap_conn.search_s(  # type: ignore
                f"cn={sram_group},ou=Groups,o={fq_co},dc=ordered,{basedn}",
                ldap.SCOPE_BASE,  # type: ignore pylint: disable=E1101
                "(objectClass=groupOfMembers)",
            )

            # Create groups
            if not cfg.state.is_known_group(dest_group_names):
                group_names = ", ".join(dest_group_names)
                plural = "s" if len(dest_group_names) > 1 else ""
                logger.debug("  Adding group%s: %s", plural, group_names)

                event_handler.add_new_groups(co, dest_group_names, group_attributes)

            cfg.state.add_groups(dest_group_names, co, sram_group, group_attributes)

            # Find members
            for _, entry in dns:  # type: ignore
                # Add members
                members: list[str] = (
                    [member.decode("UTF-8") for member in entry["member"]] if "member" in entry else []  # type: ignore
                )
                for member in members:
                    m_uid = dn_to_rdns(member)["uid"][0]
                    user = render_user_name(cfg, org=org, co=co, group=sram_group, uid=m_uid)
                    try:
                        if "login_users" not in group_attributes and not cfg.state.is_user_member_of_group(
                            dest_group_names, user
                        ):
                            event_handler.add_user_to_group(
                                org=org,
                                co=co,
                                groups=dest_group_names,
                                group_attributes=group_attributes,
                                user=user,
                            )
                    except UnkownGroup:
                        logger.error(
                            "Error in status detected. User %s was not added to group %s of CO %s.",
                            user,
                            dest_group_names,
                            co,
                        )
                    cfg.state.add_group_member(dest_group_names, user)

        except ldap.NO_SUCH_OBJECT:  # type: ignore pylint: disable=E1101
            logger.warning("service '%s' does not contain group '%s'", fq_co, sram_group)


def add_missing_entries_to_ldap(cfg: Config) -> None:
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
    dns: DNs = ldap_conn.search_s(  # type: ignore
        f"dc=ordered,{basedn}",
        ldap.SCOPE_ONELEVEL,  # type: ignore pylint: disable=E1101
        "(&(o=*)(ObjectClass=organization))",
    )

    for _, entry in dns:  # type: ignore
        fq_co = get_attribute_from_entry(entry, "o")  # type: ignore
        org, co = fq_co.split(".")
        event_handler.start_of_co_processing(co)
        logger.debug("Processing CO: %s", co)

        process_co_attributes(cfg, fq_co, org, co)
        process_user_data(cfg, fq_co, org, co)
        process_group_data(cfg, fq_co, org, co)


def remove_graced_users(cfg: Config) -> None:
    """Remove users that have passed the grace period."""

    event_handler = cfg.event_handler_proxy

    for group, group_values in cfg.state.get_known_groups_and_attributes().items():
        if "graced_users" in group_values:
            logger.debug("Checking graced users for group: %s", group)

            sram_group = group_values["sram"]["sram-group"]
            group_attributes = cfg["sync"]["groups"][sram_group]["attributes"]
            # org = cfg.state.get_org_of_known_group(group)
            co = cfg.state.get_co_of_known_group(group)

            for user, grace_until_str in group_values["graced_users"].items():  # type: ignore
                grace_until = datetime.strptime(grace_until_str, "%Y-%m-%d %H:%M:%S%z")  # type: ignore
                now = datetime.now(timezone.utc)
                if now > grace_until:
                    # The graced info for users is in status initially and needs to be
                    # copied over to new_status if it needs to be preserved. Not doing
                    # so automatically disregards this information automatically and
                    # it is the intended behaviour
                    logger.info("Grace time ended for user %s in %s", user, group)  # type: ignore
                    event_handler.remove_graced_user_from_group(
                        co=co,
                        group=group,
                        group_attributes=group_attributes,
                        user=user,  # type: ignore
                    )
                else:
                    cfg.state.set_graced_period_for_user(group, user, grace_until)  # type: ignore

                    remaining_time = grace_until - now
                    logger.info("%s from %s has %s left of its grace time.", user, group, remaining_time)  # type: ignore


def remove_deleted_users_from_groups(cfg: Config) -> None:
    """
    Determine based on the (old) status and new_status which users are to be removed.
    """

    for group in cfg.state.get_known_groups():
        co = cfg.state.get_co_of_known_group(group)
        removed_users = cfg.state.get_removed_users(group)

        remove_deleted_users_from_group(cfg, co, group, removed_users)


def remove_deleted_users_from_group(cfg: Config, co: str, group: str, users: list[str]) -> None:
    """Remove the given users from the group."""

    event_handler = cfg.event_handler_proxy

    for user in users:
        group_attributes = cfg.state.get_known_group_attributes(group)
        try:
            seconds = cfg.get_grace_period(group)
            grace_until = datetime.now(timezone.utc) + timedelta(seconds=float(seconds))
            remaining_time = grace_until - datetime.now(timezone.utc)
            logger.info(
                "User '%s' has been removed but not deleted due to grace time. Remaining time: %s",
                user,
                remaining_time,
            )
            event_handler.start_grace_period_for_user(co, group, group_attributes, user, remaining_time)
            cfg.state.set_graced_period_for_user(group, user, grace_until)

        except NoGracePeriodForGroupError:
            event_handler.remove_user_from_group(co, group, group_attributes, user)  # type: ignore


def remove_deleted_groups(cfg: Config) -> None:
    """
    Determine based on (old) status and new_status which groups are to
    be removed. If any of those groups contain members, remove those members
    first from the group.
    """

    event_handler = cfg.event_handler_proxy

    known_groups = cfg.state.get_known_groups()
    added_groups = cfg.state.get_added_groups()
    removed_groups = [group for group in known_groups if group not in added_groups]

    for group in removed_groups:
        co = cfg.state.get_co_of_known_group(group)

        users = cfg.state.get_all_known_users_from_group(group)
        remove_deleted_users_from_group(cfg, co, group, users)
        cfg.state.invalidate_all_group_members(group)

        logger.debug("Removing group: '%s'", group)
        event_handler.remove_group(co, group, cfg.state.get_known_group_attributes(group))


def remove_superfluous_entries_from_ldap(cfg: Config) -> None:
    """
    Remove entries in the destination LDAP based on the difference between
    status and new_status.
    """

    remove_deleted_groups(cfg)
    remove_graced_users(cfg)
    remove_deleted_users_from_groups(cfg)


def get_configuration_paths(path: str) -> list[str]:
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
    configuration_path: str, exception: jsonschema.exceptions.ValidationError
) -> None:
    """Display the path in the configuration where the error occured."""
    logger.error("Syntax error in configuration file  at: %s", configuration_path)

    indent = 0
    for path_element in exception.path:
        logger.error("%s%s:", " " * indent, path_element)
        indent = indent + 2
    logger.error("%s%s", " " * indent, exception.message)


@click.command(context_settings=click_ctx_settings)
@click.option(
    "-e",
    "--eventhandler-args",
    multiple=True,
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
def cli(configuration: str, debug: bool, verbose: int, eventhandler_args: tuple[str]):
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
            logger.info("Handling configuration: %s", configuration_path)

            new_eventhandler_args: dict[str, str] = {}
            for arg in eventhandler_args:
                if "=" in arg:
                    key, value = arg.split("=", 1)
                    new_eventhandler_args[key] = value
                else:
                    new_eventhandler_args[arg] = ""

            cfg = Config(configuration_path, new_eventhandler_args)

            ldap_conn = init_ldap(cfg["sram"], cfg.secrets, cfg["service"])
            cfg.set_set_ldap_connector(ldap_conn)
            cfg.last_minute_config_updates()

            add_missing_entries_to_ldap(cfg)
            remove_superfluous_entries_from_ldap(cfg)

            cfg.event_handler_proxy.finalize()

            cfg.state.dump_state()

        logger.info("Finished syncing with SRAM")
        clean_exit = True
    except (
        IOError,
        ConfigurationError,
        PasswordNotFound,
        ValueError,
        MissingUidInRenameUser,
        TemplateError,
    ) as e:
        logger.error(e)
    except ConfigValidationError as e:
        show_configuration_error(configuration_path, e)
    except jsonschema.exceptions.ValidationError as e:
        show_configuration_error(configuration_path, e)
    except ldap.NO_SUCH_OBJECT as e:  # type: ignore
        if "desc" in e.args[0]:  # type: ignore
            logger.error("%s for basedn '%s'", e.args[0]["desc"], e.args[0]["matched"])  # type: ignore
    except ldap.INVALID_CREDENTIALS:  # type: ignore
        logger.error(
            "Invalid credentials. Please check your configuration file or set SRAM_LDAP_PASSWD correctly."
        )
    except ldap.SERVER_DOWN as e:  # type: ignore
        if "desc" in e.args[0]:  # type: ignore
            logger.error(e.args[0]["desc"])  # type: ignore
    except ModuleNotFoundError as e:
        logger.error("%s. Please check your config file.", e)
    except MultipleLoginGroups:
        logger.error("Multiple login groups have been defined in the config file. Only one is allowed.")

    if not clean_exit:
        sys.exit(1)
