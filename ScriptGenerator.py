from datetime import datetime
from EventHandler import EventHandler


class ScriptGenerator(EventHandler):
    fileDescriptor = None

    requiredKeywords = ('filename', 'servicename', 'add_user_cmd', 'modify_user_cmd')

    def __init__(self, cfg):
        keywordPresent = [k in cfg.keys() for k in self.requiredKeywords]
        if all(keywordPresent):
            self.fileDescriptor = open(cfg['filename'], 'w+')
            self.addUserCmd = cfg['add_user_cmd']
            self.modifyUserCmd = cfg['modify_user_cmd']
            self.GenerateHeader(cfg['servicename'])
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
        if self.fileDescriptor:
            self.fileDescriptor.close()


    def GenerateHeader(self, serviceName):
        self.print('################')
        self.print('#')
        self.print('#  Automatically generated script by cua-sync')
        self.print(f'#  Date: {datetime.now()}')
        self.print('#')
        self.print('#  By executing this script, the CUA is synchronized with the state in SRAM')
        self.print('#  at the time this script has been generated.  The service this script was')
        self.print(f'#  generated for is: {serviceName}')
        self.print('#')
        self.print('#  This script looses its purpuse after running it and a new one must be')
        self.print(f'#  generated to sync future changes in the COs for {serviceName}.')
        self.print('#')
        self.print('"  The script might be empty, in which case there was nothing to be synced.')
        self.print('#')
        self.print('################')
        self.print('')
        self.print("set -o xtrace")
        self.print('')


    def print(self, string):
        print(string, file=self.fileDescriptor)


    def userDeleted(self, user):
        pass
