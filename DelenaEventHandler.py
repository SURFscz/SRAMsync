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

    def remove_group(self, group, attributes):
        return super().remove_group(group, attributes)

    def add_user_to_group(self, group, user, attributes: list):
        return super().add_user_to_group(group, user, attributes)

    def remove_user_from_group(self, group, user, attributes: list):
        return super().remove_user_from_group(group, user, attributes)

    def remove_graced_user(self, user):
        return super().remove_graced_user(user)

    def finialize(self):
        return super().finialize()
