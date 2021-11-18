from datetime import datetime

from SRAMsync.EventHandler import EventHandler


class CuaScriptGenerator(EventHandler):
    script_file_descriptor = None

    requiredKeywords = ("filename", "servicename", "add_user_cmd", "modify_user_cmd")
    cua_group_types = {"system_group", "project_group"}

    def __init__(self, cfg):
        self.cfg = cfg
        keywordPresent = [k in cfg.keys() for k in self.requiredKeywords]
        if all(keywordPresent):
            service = cfg["servicename"]
            script_name = f"{cfg['filename']}".format(**locals())
            self.script_file_descriptor = open(script_name, "w+")
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
        if self.script_file_descriptor:
            self.script_file_descriptor.close()

    def GenerateHeader(self):
        self.print("#" * 80)
        self.print("#")
        self.print("#  Automatically generated script by cua-sync")
        self.print(f"#  Date: {datetime.now()}")
        self.print("#")
        self.print("#  By executing this script, the CUA is synchronized with the state in SRAM")
        self.print("#  at the time this script has been generated. The service this script was")
        self.print(f"#  generated for is: {self.service_name}")
        self.print("#")
        self.print("#  This script looses its purpuse after running it and a new one must be")
        self.print(f"#  generated to sync future changes in the COs for {self.service_name}.")
        self.print("#")
        self.print("#  The script might be empty, in which case there was nothing to be synced.")
        self.print("#")
        self.print("#" * 80)
        self.print("")
        self.print("set -o xtrace")
        self.print("")
        self.print("trap quit INT")
        self.print("")
        self.print("function quit() {")
        self.print("  echo 'quiting'")
        self.print("  exit")
        self.print("}")
        self.print("")

    def print(self, string):
        print(string, file=self.script_file_descriptor)

    def start_of_service_processing(self, co):
        self.print(f"\n# service: {self.service_name}/{co}")

    def add_new_user(self, group, givenname, sn, user, mail):
        line = f"sram:{givenname}:{sn}:{user}:0:0:0:/bin/bash:0:0:{mail}:0123456789:zz:{group}"

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

    def add_new_group(self, group, attributes):
        if "system_group" in attributes:
            self.add_new_system_group(group)
        elif "project_group" in attributes:
            self.add_new_project_group(group)
        else:
            print("Could not determine group type (system_group or project_group) for {group}.")

    def add_new_system_group(self, group):
        print(f"Ignoring adding system group {group}. It should be done by the CUA team.")

    def add_new_project_group(self, group):
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

    def remove_graced_user_from_group(self, group, user, attributes):
        self.print(f"# Grace time has ended for user {user} from group {group}")
        self.remove_user_from_group(group, user, attributes)

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
                self.print(f"{self.modify_user_cmd}{remove}-a {self.service_name} {group} {user}\n")

            if "project_group" in attr:
                self.print(f"{self.modify_user_cmd}{remove}-g {group} {user}\n")
        elif l1 - l2 == 0:
            error = f"Expecting one the following attributes {self.cua_group_types} for {group}."
            raise ValueError(error)
        else:
            error = f'\'{", ".join(self.cua_group_types)}\' are mutually exclusive in the attributes of group: {group}.'
            raise ValueError(error)

    def finialize(self):
        if self.cfg["provisional_status_filename"]:
            service = self.service_name
            status_filename = self.cfg["status_filename"]
            status_filename = f"{status_filename}".format(**locals())
            provisional_status_filename = self.cfg["provisional_status_filename"]
            provisional_status_filename = f"{provisional_status_filename}".format(**locals())

            self.print("\n" + "#" * 32)
            self.print("# Cleaning provisional status. #")
            self.print("#" * 32)
            self.print(f'if [ -f "{provisional_status_filename}" ]; then')
            self.print(f'  mv "{provisional_status_filename}" "{status_filename}"')
            self.print(f"else")
            self.print(
                f"  echo 'Cannot find {provisional_status_filename}. Has this script been run before?'"
            )
            self.print("fi")

        self.print("\n" + "#" * 43)
        self.print("#" + " " * 41 + "#")
        self.print("#  Script generation ended successfully.  #")
        self.print("#" + " " * 41 + "#")
        self.print("#" * 43)
