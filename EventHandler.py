from abc import ABC, abstractmethod


class EventHandler(ABC):
    def __init__(self, generator):
        self.generator = generator


    @abstractmethod
    def start_of_service_processing(self, co):
        self.generator.start_of_service_processing(co)


    @abstractmethod
    def add_new_user(self, givenname, sn, user, mail):
        self.generator.add_new_user(givenname, sn, user, mail)


    @abstractmethod
    def add_public_ssh_key(self, user, key):
        self.generator.add_public_ssh_key(user, key)


    @abstractmethod
    def delete_public_ssh_key(self, user, key):
        self.generator.delete_public_ssh_key(user, key)


    @abstractmethod
    def add_new_group(self, group):
        self.generator.add_new_group(group)


    @abstractmethod
    def add_user_to_group(self, group, user, attributes):
        self.generator.add_user_to_group(group, user, attributes)


    @abstractmethod
    def remove_user_from_group(self, group, user, attributes: list):
        self.generator.remove_user_from_group(group, user)


    @abstractmethod
    def finialize(self):
        self.generator.finialize()
