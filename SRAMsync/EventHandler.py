from abc import ABC, abstractmethod


class EventHandler(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def start_of_service_processing(self, co):
        pass

    @abstractmethod
    def add_new_user(self, group, givenname, sn, user, mail):
        pass

    @abstractmethod
    def add_public_ssh_key(self, user, key):
        pass

    @abstractmethod
    def delete_public_ssh_key(self, user, key):
        pass

    @abstractmethod
    def add_new_group(self, group, attributes):
        pass

    @abstractmethod
    def remove_group(self, group, attributes):
        pass

    @abstractmethod
    def add_user_to_group(self, group, user, attributes):
        pass

    @abstractmethod
    def remove_user_from_group(self, group, user, attributes: list):
        pass

    @abstractmethod
    def remove_graced_user_from_group(self, group, user, attributes):
        pass

    @abstractmethod
    def finalize(self):
        pass
