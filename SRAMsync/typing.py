from typing import NewType, TypedDict, Union


class EventHandler(TypedDict):
    name: str
    config: dict[str, str]


class ConfigGroup(TypedDict):
    attributes: list[str]
    destination: list[str]


class EventHandlerConfig(TypedDict):
    event_handler_config: dict[str, str]
    secrets: dict[str, dict[str, str]]


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
