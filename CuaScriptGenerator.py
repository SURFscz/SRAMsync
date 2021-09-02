from datetime import datetime

from EventHandler import EventHandler


class CuaScriptGenerator(EventHandler):
    file_descriptor = None

    requiredKeywords = ("filename", "servicename", "add_user_cmd", "modify_user_cmd")
    cua_group_types = {"system_group", "project_group"}

    def __init__(self, cfg):
        keywordPresent = [k in cfg.keys() for k in self.requiredKeywords]
        if all(keywordPresent):
            self.file_descriptor = open(cfg["filename"], "w+")
            self.add_user_cmd = cfg["add_user_cmd"]
            self.modify_user_cmd = cfg["modify_user_cmd"]
            self.service_name = cfg["servicename"]
            self.GenerateHeader()
        else:
            className = self.__class__.__name__
            missingKeywords = list(set(self.requiredKeywords) - set(cfg.keys()))

            errorString = f"Instantion of '{className}' class takes exacly {len(self.requiredKeywords)} arguments: {', '.join(self.requiredKeywords)}. "

            if len(missingKeywords) == 1:
                errorString = errorString + f"{missingKeywords[0]} is missing."
            else:
                errorString = errorString + f"{', '.join(missingKeywords)} are missing."

            raise TypeError(errorString)

    def __del__(self):
        if self.file_descriptor:
            self.file_descriptor.close()

    def GenerateHeader(self):
        service_name = self.service_name

        self.print("#" * 80)
        self.print("#")
        self.print("#  Automatically generated script by cua-sync")
        self.print(f"#  Date: {datetime.now()}")
        self.print("#")
        self.print("#  By executing this script, the CUA is synchronized with the state in SRAM")
        self.print("#  at the time this script has been generated. The service this script was")
        self.print(f"#  generated for is: {service_name}")
        self.print("#")
        self.print("#  This script looses its purpuse after running it and a new one must be")
        self.print(f"#  generated to sync future changes in the COs for {service_name}.")
        self.print("#")
        self.print("#  The script might be empty, in which case there was nothing to be synced.")
        self.print("#")
        self.print("#" * 80)
        self.print("")
        self.print("set -o xtrace")
        self.print("")

    def print(self, string):
        print(string, file=self.file_descriptor)

    def start_of_service_processing(self, co):
        self.print(f"\n# service: {self.service_name}/{co}")

    def add_new_user(self, givenname, sn, user, mail):
        line = f"sram:{givenname}:{sn}:{user}:0:0:0:/bin/bash:0:0:{mail}:0123456789:zz:{self.service_name}"

        self.print(f"## Adding user: {user}")
        self.print(f"{self.modify_user_cmd} --list {user} ||")
        self.print(
            f'  {{\n    echo "{line}" | {self.add_user_cmd} -f-\n    {self.modify_user_cmd} --service sram:{self.service_name} {user}\n  }}\n'
        )

    def add_public_ssh_key(self, user, key):
        self.print(f"### SSH Public key: {key[:30]}...{key[-40:]}")
        self.print(f'{self.modify_user_cmd} --ssh-public-key "{key}" {user}\n')

    def delete_public_ssh_key(self, user, key):
        self.print(f"### Remove SSH Public key: {key}")
        self.print(f'{self.modify_user_cmd} -r --ssh-public-key "{key}" {user}\n')

    def add_new_group(self, group):
        line = f"sram_group:description:dummy:{group}:0:0:0:/bin/bash:0:0:dummy:dummy:dummy:"

        self.print(f"## Adding group: {group}")
        self.print(f"{self.modify_user_cmd} --list {group} ||")
        self.print(f'  {{\n    echo "{line}" | {self.add_user_cmd} -f-\n  }}\n')

    def remove_group(self, group, attributes):
        self.print("#!!! Remove group")

    def add_user_to_group(self, group, user, attributes: list):
        self.print(f"# Add {user} to group {group}")
        self.update_user_in_group(group, user, attributes, add=True)

    def remove_user_from_group(self, group, user, attributes):
        self.print(f"# Remove {user} from group {group}")
        self.update_user_in_group(group, user, attributes, add=False)

    def remove_graced_user(self, user):
        self.print(f"# Removing graced user {user}")

    def update_user_in_group(self, group, user, attributes, add):
        attr = set(attributes)
        l1 = len(attr)
        l2 = len(attr - self.cua_group_types)

        if add:
            remove = " "
        else:
            remove = " -r "

        if l1 - l2 == 1:
            if "system_group" in attr:
                self.print(f"{self.modify_user_cmd}{remove}-a delena {group} {user}\n")

            if "project_group" in attr:
                self.print(f"{self.modify_user_cmd}{remove}-g delena {group} {user}\n")
        elif l1 - l2 == 0:
            error = f"Expecting one the following attributes {self.cua_group_types} for {group}."
            raise ValueError(error)
        else:
            error = f'\'{", ".join(self.cua_group_types)}\' are mutually exclusive in the attributes of group: {group}.'
            raise ValueError(error)

    def finialize(self):
        self.print("\n" + "#" * 42)
        self.print("#" + " " * 40 + "#")
        self.print("#  Script generation ended successfully. #")
        self.print("#" + " " * 40 + "#")
        self.print("#" * 42)
