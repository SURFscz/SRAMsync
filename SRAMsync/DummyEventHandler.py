from SRAMsync.EventHandler import EventHandler


class DummyEventHandler(EventHandler):
    def __init__(self, generator):
        self.generator = generator

    def add_new_user(self, group, givenname, sn, user, mail):
        return super().add_new_user(group, givenname, sn, user, mail)

    def start_of_service_processing(self, co):
        return super().start_of_service_processing(co)

    def add_public_ssh_key(self, user, key):
        return super().add_public_ssh_key(user, key)

    def delete_public_ssh_key(self, user, key):
        return super().delete_public_ssh_key(user, key)

    def add_new_group(self, group, attributes):
        return super().add_new_group(group, attributes)

    def remove_group(self, group, attributes):
        return super().remove_group(group, attributes)

    def add_user_to_group(self, group, user, attributes: list):
        return super().add_user_to_group(group, user, attributes)

    def remove_user_from_group(self, group, user, attributes: list):
        return super().remove_user_from_group(group, user, attributes)

    def remove_graced_user_from_group(self, group, user, attributes):
        return super().remove_graced_user_from_group(group, user, attributes)

    def finialize(self):
        return super().finialize()
