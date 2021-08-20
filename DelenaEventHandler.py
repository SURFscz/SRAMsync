from EventHandler import EventHandler

class DelenaEventHandler(EventHandler):
    def add_new_user(self, givenname, sn, user, mail):
        return super().add_new_user(givenname, sn, user, mail)


    def start_of_service_processing(self, co):
        return super().start_of_service_processing(co)


    def add_public_ssh_key(self, user, key):
        return super().add_public_ssh_key(user, key)


    def delete_public_ssh_key(self, user, key):
        return super().delete_public_ssh_key(user, key)


    def add_new_group(self, group):
        return super().add_new_group(group)


    def add_user_to_system_group(self, group, user):
        return super().add_user_to_system_group(group, user)


    def add_user_to_project_group(self, group, user):
        return super().add_user_to_project_group(group, user)


    def remove_user_from_system_group(self, group, user):
        return super().remove_user_from_system_group(group, user)


    def remove_user_from_project_group(self, group, user):
        return super().remove_user_from_project_group(group, user)


    def finialize(self):
        return super().finialize()
