# SRAMsync

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-ble.svg)](http://perso.crans.org/besson/LICENSE.html)

The SRAMsync python script was originally developed in conjunction for the CUA
LDAP at SURF. Its purpose is to synchronize the SRAM LDAP, or rather a sub tree
thereof, with the CUA. The CUA has its own tooling (`sara_usertools`) to add
and modify LDAP entries and this script makes use of that tooling. However,
this does not mean this sync script can be used for the CUA only. Through
decoupling of the specific implementation and through the use of the factory
pattern new concrete implementations can be added.

The `sync-with-sram` script takes one argument; a configuration file. In case
of the CUA concrete implementation, the script outputs a bash script on
standard output. This bash script should be run after it has been created. It
contains all the necessary commands provided by `sara_usertools` to update the
CUA such that the CUA is synchronized with the SRAM LDAP.

After installation of `sync-with-sram`, the synchronization process is started
with the following command:

```bash
sync-with-sram <configuration>
```

## Installation

Use the following `pip` command to install the SYNCsram package.
```bash
pip install git+https://github.com/venekamp/SRAMsync.git#egg=SRAMsync
```

## Configuration file

The configuration file uses `yaml`. It has three top level elements: `ldap`,
`cua` and `status_filename`. The first, `ldap` tells the script where it can
find the source LDAP, i.e. the sub tree within the SRAM LDAP. While the
second element describes the commands for interacting with the CUA, what and
how groups are synced and for which groups a grace period exists. The last
element tells where to write a status file to.

```yaml
ldap:
  uri: ldaps://ldap.sram.surf.nl
  basedn: dc=<service>,dc=services,dc=sram,dc=surf,dc=nl
  binddn: cn=admin,dc=<service>,dc=services,dc=sram,dc=surf,dc=nl
  passwd: VerySecretPassword!
cua:
  servicename: <myservice>
  groups:
    - <project>_login:
        {
            attributes: ["system_group", "grace_period", "login_users"],
            destination: "<project>_login"
        }
    - <project>_cpu: { attributes: ["system_group"], destination: "<project>_cpu" }
    - <project>_gpu_v100: { attributes: ["system_group"], destination: "<project>_gpu_v100" }
    - user: { attributes: ["project_group"], destination: "sram-project-{co}-user" }
    - data: { attributes: ["project_group"], destination: "sram-project-{co}-data" }
    - sw: { attributes: ["project_group"], destination: "sram-project-{co}-sw" }
    - dcache: { attributes: ["ignore"], destination: "dcache" }
    - intelc: { attributes: ["ignore"], destination: "intelc" }
  generator:
    generator_type: <MyGenerator>
    event_handler: <MyEventHandler>
    input:
      filename: script.sh
      add_user_cmd: sudo sara_adduser --no-usermail
      modify_user_cmd: sudo sara_modify_users --no-usermail
  grace:
    sram-<project>-login:
      grace_period: 90
status_filename: "/home/<user>/status.json"
```

### LDAP config element

This part of the configuration file is rather staight foreward. It describes
where to find the SRAM LDAP by its `uri`, the necessary `basedn`, `binddn` and
`passwd` to get access to sub tree of the SRAM LDAP.

### CUA config element

The cua element is slightly more complicated. First it contains the commands
for executing LDAP add and modify commands. The sync script will complement
these commands to create the full commands.

The next part `groups`, consists out of a number of key value pairs. The key
tells what groups need to be synced. These are the names as they appear in the
SRAM LDAP. `<project>` is a placeholder and you can name groups anyway you'd
like. They are just presented as an example.

One could use `{service}` as a placeholder for the `servicename`. Thus the
following group sync definition:

```yaml
cua:
  servicname: my-project
  groups:
    - project_login:
      {
        attributes: ["none"],
        destination: "{serivce}_login}
      }
```

is the same as:

```yaml
cua:
  servicname: my-project
  groups:
    - project_login:
      {
        attributes: ["none"],
        destination: "my-project_login}
      }
```

The `attribute` element within the `groups` section must be specfied at all
times. If it is missing an error will be generated. In case there is no need
for attributes, it is okay to use `["none"]` or any other value to indicate
that there are no attributes defined.

The value part after the `:` tells how the group name must be mapped to the
CUA. For the CUA we have agreed on the `sram-` prefix for example. For some
groups we want to have more information in the CUA group name and we do so by
adding the SRAM organisation `{org}` and SRAM CO `{co}` tags. This way, we are
able to create unique names within the CUA, and thus prevent clashing with
other users. The CUA has two different types of groups, which require a
slightly different set of arguments. This distinction is made in the part
before the `:`. Either a group is a system `system` type, or a project
`project` type. A third type is allowed for conveniences. That is the `ignore`
and tells the sync script to simply ignore this group. One could of course not
list those groups in the configuration file. It will have the same effect.

The final part within the `cua` element is the `grace` element. Here you list
the groups that have a grace period, i.e. a period in which users have been
removed from the SRAM group, but need to linger a bit longer on te CUA side.
Don't use the SRAM group name, instead use the full name as it appears in the
CUA. The accompanying `grace_period` is in days.

Lastly, the `'status_filename` tells the sync script where to read and write
a status file. This will be discussed in the next session.

## Status file

The sync script needs to keep track of what it already has done. It keeps this
tracking information inside a json formatted status file. It basically reflects
the current status of CUA. Well, not the entire CUA of course, only the part
related to the groups defined in the configuration file. In it you'll find a
`users` and `groups` part. Inside the `users` part you'll find a `line` for
each user. This is specific to the `sara_usertools`. It contains user
information and is handled by the `sara_usertools`. You might find a
`sshPublicKey` for a user. If that user has a public SSH key in their SRAM
profile it will be listed here. If a user should update their public SSH key,
the sync script can compare the new and old values and perform an update if
they differ.

The `group` part contains information about what members are part of that group
and attributes of that group. These are the attributes: `sys`, `prj`, and
`grace` from the configuration file. They are translated as `system_group`,
`project_group` and `grace`. When users a being added or removed to or from
groups in SRAM, the sync script picks this up by comparing the old members with
the new ones and if there is a difference creates the appropriate command to
reflect that change. The generated commands are executed when running the
resulting script.

In case a group has the `grace` attribute, and additional element will be
present when users are removed from that group. Graced information is tracked
with the `graced` element. In it you'll find key values pairs. The key is the
user and the value the time stamp in UTC at which point in time the user has
been removed from the group. As long as the time stamp of the user plus the
grace period for the group has not exceeded past the current time, the user
keep being a member of this group. However, upon passing the grace period the
appropriate command for removal is generated in the output of the sync script
and upon executing the resulting script, the user is removed from the group in
the CUA.

The final action of the sync script is to write the new current and updated
status to the status file.

### Removal of the status file

In case the status file is removed or otherwise lost or not up to date, it can
be safely be removed. Running the `cua_sync.py` script then generates all the
`sara_usertools` commands to repopulate the CUA. This is safe because the sync
script also generates commands that check first if LDAP entries already exists.
After running the sync script with an empty or non-existing status file, the
new status file reflects the current state of the CUA again.

## Final remarks

The sync script has be tested with python 3.5.3 and with the
future_fstrings (1.2.0) package. When using Python 3.6 or above, the
future_fstrings should not be necessary.
