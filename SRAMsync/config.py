"""
  Configuration definition and validating. The config class defines
  the main configuration. EventHandler classes may extent the
  configuration.
"""

from datetime import timedelta
import re
from typing import Any, List

from jsonschema import validate
import ldap
from ldap import ldapobject
import yaml

from SRAMsync.common import deduct_event_handler_class, get_attribute_from_entry
from SRAMsync.event_handler import EventHandler
from SRAMsync.event_handler_proxy import EventHandlerProxy
from SRAMsync.state import NoGracePeriodForGroupError, State


class ConfigurationError(Exception):
    """Exception class representing configuration errors."""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def get_status_object(cfg: dict, **kwargs: str) -> State:
    """Return the configured status object."""
    state_class = deduct_event_handler_class(cfg["name"])
    state_object = state_class(cfg["config"], **kwargs)
    return state_object


def to_seconds(raw_period: str) -> int:
    """Convert the raw_period string into seconds."""
    units = {"d": 86400, "m": 2592000, "H": 3600, "M": 60, "s": 1}
    last = raw_period[-1]

    try:
        seconds = float(raw_period) * 86400
    except ValueError:
        if last in units:
            seconds = float(raw_period[:-1]) * units[last]
        else:
            coluns = raw_period.count(":")
            if coluns == 3:
                days, hours, minutes, seconds = raw_period.split(":")
            elif coluns == 2:
                days = 0
                hours, minutes, seconds = raw_period.split(":")
            else:
                days = 0
                seconds = 0
                hours, minutes = raw_period.split(":")

            seconds = timedelta(
                days=int(days), hours=int(hours), minutes=int(minutes), seconds=int(seconds)
            ).total_seconds()

    return int(seconds + 0.5)


class Config:
    """
    Class for defining and handling the configuration for sync-with-sram.
    The configuration file must be in JSON and a JSON schema is defined
    and used for validating a configuration file.
    """

    _schema = {
        "$schema": "http://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "service": {"type": "string"},
            "secrets": {
                "type": "object",
                "properties": {"file": {"type": "string"}},
                "required": ["file"],
                "additionalProperties": False,
            },
            "sram": {
                "type": "object",
                "properties": {
                    "uri": {"type": "string"},
                    "basedn": {"type": "string"},
                    "binddn": {"type": "string"},
                    "passwd": {"type": "string"},
                    "passwd_from_secrets": {"type": "boolean"},
                },
                "required": ["uri", "basedn", "binddn"],
                "not": {"required": ["passwd", "passwd_from_secrets"]},
                "additionalProperties": False,
            },
            "sync": {
                "type": "object",
                "properties": {
                    "users": {
                        "type": "object",
                        "properties": {
                            "rename_user": {
                                "oneOf": [
                                    {"type": "string"},
                                    {
                                        "type": "object",
                                        "properties": {
                                            "default": {"type": "string"},
                                            "groups": {"type": "object"},
                                        },
                                        "required": ["groups"],
                                        "additionalProperties": False,
                                    },
                                ],
                            },
                            "aup_enforcement": {"type": "boolean"},
                        },
                        "required": ["rename_user"],
                        "additionalProperties": False,
                    },
                    "groups": {
                        "type": "object",
                        "patternProperties": {
                            ".*": {
                                "type": "object",
                                "properties": {
                                    "attributes": {"type": "array", "items": {"type": "string"}},
                                    "destination": {
                                        "oneOf": [
                                            {"type": "string"},
                                            {"type": "array", "items": {"type": "string"}},
                                        ]
                                    },
                                },
                                "required": ["attributes", "destination"],
                            },
                        },
                    },
                    "event_handler": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "config": {"type": "object"},
                            },
                            "required": ["name"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["users", "event_handler"],
                "additionalProperties": False,
            },
            "status": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "config": {"type": "object"},
                },
                "required": ["name", "config"],
                "additionalProperties": False,
            },
        },
        "required": ["service", "sram", "sync", "status"],
        "additionalProperties": False,
    }

    def __init__(self, config_file: str, **args) -> None:
        with open(config_file, encoding="utf8") as fd:
            config = yaml.safe_load(fd)

        validate(schema=self._schema, instance=config)

        if "@all" not in config["sync"]["groups"]:
            config["sync"]["groups"]["@all"] = {"attributes": [], "destination": []}

        self.config = config

        self.secrets = {}
        if "secrets" in config:
            with open(config["secrets"]["file"], encoding="utf8") as fd:
                self.secrets = yaml.safe_load(fd)

        self.state = get_status_object(config["status"], service=config["service"])

        event_handlers = self.get_event_handlers(self.state, **args)
        self.event_handler_proxy = EventHandlerProxy(event_handlers)

    def __getitem__(self, item: str) -> Any:
        return self.config[item]

    def __contains__(self, item: str) -> bool:
        return item in self.config

    def last_minute_config_updates(self) -> None:
        """
        Depending on what is exactly configured, it might be the case that some
        parts of the config file need to be expanded. This needs to be done
        before the config file can be used by the main loop. However, some
        functionality might require some other initialization, such as an LDAP
        connection, that the configiration update can only happend at the last
        minute.
        """
        self._remove_ignored_groups()
        self._expand_groups()
        self._group_destintion_to_list()
        self._normalize_grace_periods()

    def get_event_handlers(self, state: State, **args: dict) -> List[EventHandler]:
        """
        Dynamically load the configured class from the configuration. If the class
        expects a configuration extract that from the configuration and pass it
        along at instansiation time. Put the status_filename and the optional
        provisional_status_filename in the class configuration.
        """

        event_handler_section = self.config["sync"]["event_handler"]

        event_handler_instances = []
        for event in event_handler_section:
            event_handler_class = deduct_event_handler_class(event["name"])

            event_handler_cfg = {}
            if "config" in event:
                event_handler_cfg["event_handler_config"] = event["config"]

            if hasattr(self, "secrets"):
                event_handler_cfg["secrets"] = self.secrets

            event_handler_instance = event_handler_class(
                self.config["service"], event_handler_cfg, state, ["sync", "event_handler", "config"], **args
            )

            event_handler_instances.append(event_handler_instance)

        return event_handler_instances

    def get_sram_basedn(self) -> str:
        """Get the base DN"""
        return self.config["sram"]["basedn"]

    def get_ldap_connector(self) -> ldapobject.LDAPObject:
        """Get the LDAP connector."""
        if self._ldap_connector:
            return self._ldap_connector

        raise ConfigurationError("ldap_connection is uninitialized.")

    def set_set_ldap_connector(self, ldap_connector: ldapobject.LDAPObject) -> None:
        """Set the LDAP connector."""
        self._ldap_connector = ldap_connector

    def get_grace_period(self, group: str) -> int:
        """Get the defined grace period for group in seconds."""
        re_grace_period = "grace_period=[0-9]+"

        last_known_state = self.state.get_last_known_state()
        for attribute in last_known_state["groups"][group]["attributes"]:
            if re.search(re_grace_period, attribute):
                _, seconds = attribute.split("=")
                return seconds

        raise NoGracePeriodForGroupError

    def _normalize_grace_periods(self) -> None:
        """
        Check all defined attributes for all groups in the configuration file
        for the occurrence of a grace_period attribute. If found, normalize it
        by taking the right hand side of the '=' sign and create a new grace_period
        item for that group in the configuration with the grace period in seconds.
        """
        re_grace_period = re.compile(
            r"""
            ^grace_period=   # Must start with grace_period=
            (?:
            (?:[0-9]+(?:\.[0-9]+)?[s|d|H|M|m]?)$      # Interger or float, might end with suffix
            |                                          # alternative duration notation
            (?:[0-9]+:)?(?:2[0-3]|[01]?[0-9]):(?:[0-5][0-9])(?::[0-5][0-9])?)$  # HH:MM notation
            """,
            re.VERBOSE,
        )

        if "groups" not in self.config["sync"]:
            return

        groups = self.config["sync"]["groups"]

        for group, values in groups.items():
            for i, attribute in enumerate(values["attributes"]):
                if attribute == "grace_period":
                    raise ValueError("grace_period attribute found without a value. Check configuration.")

                if re_grace_period.match(attribute):
                    _, raw_period = attribute.split("=")
                    grace_period = to_seconds(raw_period)

                    groups[group]["attributes"][i] = f"grace_period={grace_period}"
                elif attribute.startswith("grace_period="):
                    raise ValueError("grace_period has wrong value.")

    def _remove_ignored_groups(self) -> None:
        """Remove any group when the ignore attributes is defined."""
        ignored_groups = [
            group
            for group, values in self.config["sync"]["groups"].items()
            if "ignore" in values["attributes"]
        ]

        for group in ignored_groups:
            del self.config["sync"]["groups"][group]

    def _expand_groups(self) -> None:
        """
        Some group definition can be a regular expression instead of a constant
        string. These regular expression need to be exapanded to a new line in
        the config file. In order to do this, a lookup needs to be done for all
        known group names in SRAM. When the regural expression matches an SRAM
        group name, then for this group a new line is added to the
        configuration file that is in memory.
        """
        regex_groups = {
            re.compile(group): values
            for group, values in self.config["sync"]["groups"].items()
            if "regex_groups" in values["attributes"]
        }

        fq_cos = self._retieve_fully_qualified_cos()
        basedn = self.get_sram_basedn()
        groups = set()

        for fq_co in fq_cos:
            dns = self._ldap_connector.search_s(
                f"ou=Groups,o={fq_co},dc=ordered,{basedn}",
                ldap.SCOPE_ONELEVEL,  # type: ignore pylint: disable=E1101
                "(objectClass=groupOfMembers)",
            )

            for _, entry in dns:  # type: ignore
                group_name = get_attribute_from_entry(entry, "cn")

                groups.add(group_name)

        new_groups = {}
        for regex, value in regex_groups.items():
            for group in groups:
                if regex.match(group):
                    new_groups[group] = value

        if new_groups:
            all_groups = self.config["sync"]["groups"]

            if all_groups.keys() > new_groups.keys():
                n = ", ".join(list(new_groups.keys()))
                if len(new_groups) == 1:
                    a = "a configured group name: {}".format(n)
                else:
                    a = "configured group names: {}".format(n)
                raise ConfigurationError(
                    f"A regular expression matches {a}. Please, check your configuration."
                )

            self.config["sync"]["groups"] = {
                group: config
                for group, config in all_groups.items()
                if "regex_groups" not in config["attributes"]
            }
            self.config["sync"]["groups"].update(new_groups)

            validate(schema=self._schema, instance=self.config)

    def _retieve_fully_qualified_cos(self) -> List[str]:
        """Retrieve all organization.co that are known to the services."""
        basedn = self.get_sram_basedn()

        dns = self._ldap_connector.search_s(
            f"dc=ordered,{basedn}",
            ldap.SCOPE_ONELEVEL,  # type: ignore pylint: disable=E1101
            "(&(o=*)(ObjectClass=organization))",
        )

        fully_quallified_cos = []
        for _, entry in dns:  # type: ignore
            fully_quallified_cos.append(get_attribute_from_entry(entry, "o"))

        return fully_quallified_cos

    def _group_destintion_to_list(self) -> None:
        """Make the destination a list in case it is defined as a string."""
        groups = self.config["sync"]["groups"]
        dest_as_string = [group for group in groups if isinstance(groups[group]["destination"], str)]

        for group_name in dest_as_string:
            groups[group_name]["destination"] = [groups[group_name]["destination"]]
