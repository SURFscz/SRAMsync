from typing import NewType, TypedDict, Union
from typing_extensions import NotRequired


class MessageContent(TypedDict):
    important: bool
    messages: set[str]


COmessage = dict[str, MessageContent]
Message = dict[str, COmessage]


class SMTPconfig(TypedDict):
    host: str
    port: int
    login: NotRequired[str]
    passwd: NotRequired[str]


class ConfigGroup(TypedDict):
    attributes: list[str]
    destination: list[str]


Secrets = TypedDict("Secrets", {"sram-ldap": dict[str, str], "smtp": dict[str, dict[str, str]]})


class HeaderLine(TypedDict):
    header: str
    line: str


EmailHeaders = TypedDict(
    "EmailHeaders",
    {
        "mail-to": str,
        "mail-from": str,
        "mail-message": str,
        "mail-subject": str,
    },
)
report_events = TypedDict(
    "report_events",
    {
        "start-co-processing": HeaderLine,
        "add-new-user": HeaderLine,
        "add-group": HeaderLine,
        "add-user-to-group": HeaderLine,
        "remove-user-from-group": HeaderLine,
        "remove-graced-user-from-group": HeaderLine,
        "finalize": HeaderLine,
    },
)


class EmailNotificationConfig(EmailHeaders):
    aggregate_mails: bool
    collect_events: bool
    smtp: SMTPconfig
    report_events: report_events


class CuaNotificationsConfig(TypedDict):
    filename: str
    add_cmd: str
    modify_cmd: str
    check_cmd: str
    sshkey_cmd: str


class CbaNotificationConfig(TypedDict):
    cua_config: CuaNotificationsConfig
    cba_budget_account: str
    cba_machine: str
    cba_add_cmd: str
    cba_del_cmd: str


class DummyEventHandler(TypedDict):
    pass


class EventHandlerConfig(TypedDict):
    event_handler_config: Union[
        EmailNotificationConfig, CuaNotificationsConfig, CbaNotificationConfig, DummyEventHandler
    ]
    secrets: Secrets


class EventHandler(TypedDict):
    name: str
    config: EventHandlerConfig


class Sync(TypedDict):
    event_handler: list[EventHandler]
    groups: dict[str, dict[str, ConfigGroup]]
    users: dict[str, Union[bool, str]]


class StatusFilenames(TypedDict):
    status_filename: str
    provisional_status_filename: str


class StatusConfig(TypedDict):
    config: StatusFilenames
    name: str


class Config(TypedDict):
    service: str
    secrets: dict[str, str]
    sram: dict[str, str]
    sync: Sync
    status: StatusConfig
    attributes: list[str]
    destination: list[str]


SRAM = TypedDict("SRAM", {"CO": str, "sram-group": str, "org": str})


class StateUser(TypedDict):
    CO: str
    sshPublicKey: list[str]


class StateGroup(TypedDict):
    attributes: list[str]
    members: list[str]
    sram: SRAM
    graced_users: dict[str, str]


class StateFile(TypedDict):
    users: dict[str, StateUser]
    groups: dict[str, StateGroup]


DNs = NewType(name="DNs", tp=list[tuple[str, dict[str, list[bytes]]]])
