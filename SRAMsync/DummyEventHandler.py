from .SRAMlogger import logger
from .EventHandler import EventHandler


class DummyEventHandler(EventHandler):
    def __init__(self, cfg):
        logger.debug("DummyEventHandler.__init__(cfg)")
        logger.debug(cfg)
        pass

    def add_new_user(self, group, givenname, sn, user, mail):
        logger.debug(f"  add_new_user({group}, {givenname}, {sn}, {user}, {mail}")
        return

    def start_of_service_processing(self, co):
        logger.debug(f"  start_of_service_processing({co})")
        return

    def add_public_ssh_key(self, user, key):
        logger.debug(f"    add_public_ssh_key({user}, {key})")
        return

    def delete_public_ssh_key(self, user, key):
        logger.debug(f"    delete_public_ssh_key({self}, {user}, {key})")
        return

    def add_new_group(self, group, attributes):
        logger.debug(f"  add_new_group({group}, {attributes})")
        return

    def remove_group(self, group, attributes):
        logger.debug(f"  remove_group({group}, {attributes})")
        return

    def add_user_to_group(self, group, user, attributes: list):
        logger.debug(f"  add_user_to_group({group}, {user}, {attributes})")
        return

    def remove_user_from_group(self, group, user, attributes: list):
        logger.debug(f"  remove_user_from_group({group}, {user}, {attributes})")
        return

    def remove_graced_user_from_group(self, group, user, attributes):
        logger.debug(f"  remove_graced_user_from_group({group}, {user}, {attributes})")
        return

    def finalize(self):
        logger.debug(f"  finalize()")
        return
