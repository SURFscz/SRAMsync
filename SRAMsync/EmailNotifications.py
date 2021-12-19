from SRAMsync.EventHandler import EventHandler


class EmailNotifications(EventHandler):
    def __init__(self, cfg):
        pass

    def add_new_user(self, group, givenname, sn, user, mail):
        pass

    def start_of_service_processing(self, co):
        pass

    def add_public_ssh_key(self, user, key):
        pass

    def delete_public_ssh_key(self, user, key):
        pass

    def add_new_group(self, group, attributes):
        pass

    def remove_group(self, group, attributes):
        pass

    def add_user_to_group(self, group, user, attributes: list):
        pass

    def remove_user_from_group(self, group, user, attributes: list):
        pass

    def remove_graced_user_from_group(self, group, user, attributes):
        pass

    def finialize(self):
        pass
