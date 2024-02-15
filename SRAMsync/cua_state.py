from state import State


class CuaState(State):
    def __init__(self):
        """
        Initialze access to the CUA
        """
        pass

    def __getitem__(self, key: str) -> Any:
        """Return item."""

    def __setitem__(self, key: str, value: Any) -> None:
        """Set value"""

    def dump_state(self) -> None:
        """Dump the current state."""

    def get_last_known_state(self) -> dict:
        """Return the last known state."""

    def is_known_user(self, user: str) -> bool:
        """Check if the user is known from the last state."""

    def is_known_group(self, groups: List[str]) -> bool:
        """Check if the group is known from the last state."""

    def is_user_member_of_group(self, dest_group_names: List[str], user: str) -> bool:
        """Check is the user is member of the destination group."""

    def is_found_group(self, group: str) -> bool:
        """Check if the group is in the encounterd groups."""

    def add_user(self, user: str, co: str) -> None:
        """Add user."""

    def add_groups(
        self, dest_group_names: List[str], co: str, sram_group: str, group_attributes: list
    ) -> None:
        """Add a new group."""

    def add_group_member(self, dest_group_names: List[str], user: str) -> None:
        """Add member to a group."""

    def get_all_known_users_from_group(self, group) -> List[str]:
        """Get all users from the known group."""

    def get_added_group(self, group: str) -> dict:
        """Get added group."""

    def get_added_groups(self) -> list:
        """Get added groups."""

    def get_org_of_known_group(self, group) -> str:
        """Get the CO name of the known group."""

    def get_co_of_known_group(self, group) -> str:
        """Get the CO name of the known group."""

    def get_known_group(self, group: str) -> dict:
        """Get known group."""

    def get_known_groups(self) -> list:
        """Get known groups."""

    def get_known_group_attributes(self, group: str) -> list:
        """Get attributes for known group."""

    def get_known_groups_and_attributes(self) -> dict:
        """Get all known groups and their attributes."""

    def get_removed_users(self, group: str) -> list:
        """Get the users that have been removed since the last synchronisation for the group."""

    def get_known_user_public_ssh_keys(self, user: str) -> set:
        """Get the set of known public ssh keys for the user."""

    def set_user_public_ssh_keys(self, user: str, ssh_public_keys: set) -> None:
        """Set the public ssh keys for the user."""

    def set_graced_period_for_user(self, group: str, user: str, grace_period: datetime) -> None:
        """Set the grace period for the user in group group."""

    def invalidate_all_group_members(self, group: str):
        """If necessay, invalidate all group members."""
