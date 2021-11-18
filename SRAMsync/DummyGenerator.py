from SRAMsync.EventHandler import EventHandler


class TemplateGenerator(EventHandler):
    def __init__(self, cfg):
        pass

    def add_new_user(self, givenname, sn, user, mail):
        pass

    def start_of_service_processing(self, co):
        pass

    def add_public_ssh_key(self, user, key):
        pass

    def delete_public_ssh_key(self, user, key):
        pass

    def add_new_group(self, group):
        pass

    def add_user_to_system_group(self, group, user):
        pass

    def add_user_to_project_group(self, group, user):
        pass

    def remove_user_from_system_group(self, group, user):
        pass

    def remove_user_from_project_group(self, group, user):
        pass

    def finialize(self):
        pass
