from typing import TypedDict, Union


class EventHandler(TypedDict):
    config: dict[str, str]
    name: str


class ConfigGroup(TypedDict):
    attributes: list[str]
    destination: str


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


class SRAM(TypedDict):
    CO: str
    sram_group: str


class StateUser(TypedDict):
    CO: str
    sshPublicKey: set[str]


class StateGroup(TypedDict):
    attributes: list[str]
    members: list[str]
    sram: SRAM


class StateFile(TypedDict):
    users: dict[str, StateUser]
    groups: dict[str, StateGroup]
