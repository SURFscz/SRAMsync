# SRAMsync

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-ble.svg)](http://perso.crans.org/besson/LICENSE.html)
[![CI](https://github.com/SURFscz/SRAMsync/actions/workflows/ci.yml/badge.svg)](https://github.com/SURFscz/SRAMsync/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SURFscz/SRAMsync/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/SURFscz/SRAMsync/actions/workflows/codeql-analysis.yml)

## Table of Contents

<!-- vim-markdown-toc GFM -->

* [Purpose of SRAMsync](#purpose-of-sramsync)
* [Installation](#installation)
* [Invocation](#invocation)
* [Structure of sync-with-sram](#structure-of-sync-with-sram)
* [Configuration details](#configuration-details)
  * [Multiple configurations](#multiple-configurations)
  * [SRAM connection details](#sram-connection-details)
    * [Password file format](#password-file-format)
      * [SRAM LDAP passwords](#sram-ldap-passwords)
      * [SMTP password](#smtp-password)
    * [Environment variable](#environment-variable)
  * [Synchronization details](#synchronization-details)
    * [aup_enforcement](#aup_enforcement)
    * [users](#users)
      * [Multiple conversions](#multiple-conversions)
    * [groups](#groups)
    * [Mapping a group to multiple destinations](#mapping-a-group-to-multiple-destinations)
    * [Predefined attributes](#predefined-attributes)
    * [event_handler](#event_handler)
* [Keeping track of the current state](#keeping-track-of-the-current-state)
* [Putting it together](#putting-it-together)
  * [Notes for the above example](#notes-for-the-above-example)
* [Variable substitution](#variable-substitution)
  * [Available variables](#available-variables)
* [Removal of the status file](#removal-of-the-status-file)
* [Logging](#logging)
* [EventHandler Classes](#eventhandler-classes)
  * [DummyEventandler](#dummyeventandler)
  * [CuaScriptGenerator](#cuascriptgenerator)
    * [CuaScriptGenerator configuration](#cuascriptgenerator-configuration)
  * [EmailNotifications](#emailnotifications)
    * [EmailNotifications configuration](#emailnotifications-configuration)
    * [Supported command line options](#supported-command-line-options)
  * [Creating a custom EventHandler](#creating-a-custom-eventhandler)
* [Events](#events)
  * [When are events emitted](#when-are-events-emitted)
    * [start-co-processing](#start-co-processing)
    * [add-new-user](#add-new-user)
    * [add-public-ssh-key](#add-public-ssh-key)
    * [delete-public-ssh-key](#delete-public-ssh-key)
    * [add-new-group](#add-new-group)
    * [remove-group](#remove-group)
    * [add-user-to-group](#add-user-to-group)
    * [start-grace-period-for-user](#start-grace-period-for-user)
    * [remove-graced-user-from-group](#remove-graced-user-from-group)
    * [remove-user-from-group](#remove-user-from-group)
    * [finalize](#finalize)
* [Acknowledgment](#acknowledgment)

<!-- vim-markdown-toc -->
## Purpose of SRAMsync

SRAMsync is an LDAP synchronization script written in Python. Originally it was
developed for synchronization between [SRAM](https://sbs.sram.surf.nl) and an
LDAP at SURF, such that different SURF Research services would be able to
obtain user attributes and grant users access to the services. The first
versions were tailored towards the specific needs of SURF, version 2 takes
things a little further and generalizes a few pieces a bit more such that its
applicability is extended.

## Installation

The SRAMsync package can be installed by pip. Use the following to install
the latest from the *main* branch on GitHub:

```bash
pip install git+https://github.com/SURFscz/SRAMsync.git#egg=SRAMsync
```

If you wish to use a specific version you should use the following:

```bash
pip install git+https://github.com/SURFscz/SRAMsync.git@v3.0.0#egg=SRAMsync
```

The exact versions, i.e. the  *@v3.0.0* in the above url, can be found the
[tags page](https://github.com/venekamp/SRAMsync/tags) at GitHub.

## Invocation

The SRAMsync package contains an executable called: `sync-with-sram`. It takes
a single argument and options. This argument is either a YAML configuration
file that tells where to find the LDAP to sync from, baseDN, bindDN and
password, or it is a path to a directory containing at least one configuration
file. The configuration file also tells what groups need to be synced and what
they will be called in the destination LDAP.

## Structure of sync-with-sram

The `sync-with-sram` consists of a main loop that iterates over the SRAM
LDAP as defined per configuration. The main loop does not do anything more than
this iteration. For example, it does not write entries into a destination LDAP.
In fact, the main loop in unaware what it should do with all encountered
entries. All it does is emitting events when some action should be required.
Events are triggered when for example the main loop detects that a new user is
added to SRAM. Now it is up to whoever is responsible for dealing with such an
event and what it really means. In case of a new user this should ultimately
end with a user being added to some destination LDAP, but it is not the
responsibility of the main loop. Instead the configuration requires an
`EventHandler` class to be instantiated that takes care of this functionality.

A design choice was to dynamically load derived `EventHandler` classes. Thereby
allowing for multiple implementations of emitted events. This allows for
flexibility such that `sync-with-sram` can be invoked for any number of
environments which need to synchronize SRAM LDAP attributes. Although,
`sync-with-sram` started out as an LDAP to LDAP synchronization process, given
its design the destination end does not need to be an LDAP. It is up to an
`EventHandler` class to decide what needs to be done.

## Configuration details

The executable `sync-with-sram` needs a configuration file in order to know
what and how to sync. The configuration is done in YAML. At the highest level
the configuration looks as follows:

```yaml
service: <service name>
secrets:
  file: <path to secrets file>
sram:
   <connection details>
sync:
   <synchronization details>
status:
  <status details>
```

As can be noticed from the above, five parts can be identified:

1. `service:` Define the service name
2. `secrets:` Configuration details concerning secrets
3. `sram:` Connection details for SRAM
4. `sync:` What and how to synchronize
5. `status:` How to keep track of the current state of the synchronization process

The `secrets` part is optional. However, if omitted, one does need to put any
passwords in the configuration file itself. The exception to this is for the
passwd of SRAM LDAP. In this case, one could use the environment variable
`SRAM_LDAP_PASSWD`. Note however that for any other passwords in the
configuration file the use of environment variables in unavailable. For those
cases, either use the `secrets` file, or put passwords in plain text into the
configuration file.

### Multiple configurations

If a service provide supports multiple services and each service needs to be
synchronized, it is possible to put all those configuration files into a single
directory and instead of calling `sync-with-sram` with a single configuration
file, use the directory instead. `sync-with-sram` will loop over all `*.yml`
and `*.yaml` files in that directory and consider them to be configuration
files.

### SRAM connection details

The script needs to know how it should connect to the SRAM LDAP. As a service
you are allowed to read, not write, from a sub tree in LDAP that has been
created for your service. You should have been given a base DN and accompanying
bind DN and passwd. The full specification of the `sram:` key is as follows:

```yaml
sram:
  uri: ldaps://ldap.sram.surf.nl
  basedn: dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  binddn: cn=admin,dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  passwd_from_secrets: true or false
```

or, if you wish to include the bind DN password in the configuration file:

```yaml
sram:
  uri: ldaps://ldap.sram.surf.nl
  basedn: dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  binddn: cn=admin,dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  passwd: <your password>
```

Please note that for the former, you must include the `secrets` section as
well. See next section.

#### Password file format

The password file can contain passwords for multiple sources. The file name is
configured in the `secrets` block. Currently only loading passwords from file
is supported. The `secrets` block is defines as follows:

```yaml
secrets:
  file: <file name>
```

When the above is specified in the configuration file, the secrets in it will
be loaded regardless of being used in the configuration file. One could have
the secrets being loaded and still use plain text passwords for for example the
SRAM LDAP. Currently it can hold passwords for both the SRAM LDAP and for SMTP
connections. Each source has its own part in the password file. All SRAM LDAP
related passwords for example are grouped under `sram-ldap`, while the SMTP
passwords are bundled under `smtp`. Below is an example of a password file.

```yaml
sram-ldap:
  my_service_A: "fh9dFDSf67fsd;fdsgh"
  my_service_B: "uirweSD_3$Afdhs!^Z1"
smtp:
  mail.google.com:
    jane.doe: "fsdf,mm$$fgsff"
```

If you don't use the `EmailNotifications` class for sending notification by e-mail,
you don't have to have the `smtp` block in your password file.

##### SRAM LDAP passwords

The passwords for the SRAM LDAP are listed as key value pairs. The key is the name
of the service, i.e. the `service` part in a `sync-with-sram` configuration and the
value is the password for the SRAM LDAP sub tree.

##### SMTP password

The SMTP passwords take a slightly more complex structure then the key value
pairs of SRAM LDAP passwords. For SMTP you need the FQDN, i.e. hostname and
domain name, of the SMTP host and the login account name. Login account names
and the associated password form a key value pair and are grouped under the
SMTP FQDN.

#### Environment variable

One could also use an environment variable (SRAM_LDAP_PASSWD) containing the
SRAM LDAP password. If it is specified it take precedence over either `passwd`
or `passwd_file`. If neither `passwd` nor `passwd_file` is specified in the
configuration, the environment variable must be present. If not an error is
shown.

### Synchronization details

The `sync:` holds all information regarding what to sync and in which way.
Within this key there are four keys: `aup_enforcement`, `users`, `groups:` and
`event_handler:`. Thus on a high level, the `sync:` block look like this:

```yaml
sync:
  aup_enforcement: <boolean>
  users:
    rename_user: <template string>
  groups:
    <group synchronization information>
  event_handler:
    - name: <SRAMsync event handler class name to instantiate>
      config:
        <configuration belonging to the instantiated EventHandler class>
    - name: <another event handler name>
      config: <config for this event handler>
```

#### aup_enforcement

Service providers can request SRAM to have users accept an Acceptable User
Policy (AUP). If this is the case, then by setting the `aup_enforcement` key to
`true`, SRAMsync will check this value. SRAMsync uses this value, amongst
others, to determine if a user should be provisioned. If a user has not
accepted the AUP, then the receiving end of the synchronization will not be
informed about this user. Once the user has accepted the AUP in SRAM, the
receiving end will be notified when the synchronization is run.

#### users

The naming convention is configurable and a template can be used to customize
the conversion. Its purpose is to create non conflicting users names at the
destination. The `uid` from SRAM is unique within SRAM, but that does not
guarantee that it will be unique at the destination. The following variables
can be used to better tailor what is needed:

* `{service}`
* `{org}`
* `{co}`
* `{uid}`

If you would like to add a prefix to the destination name and include CO
information you could do something like this:

```yaml
users:
  rename_user: "sram-{co}-{uid}"
```

The `{uid}` *must* be included to ensure uniqueness. If it is missing an error
is displayed and the sync will be aborted.

##### Multiple conversions

In case you need to differentiate in naming conventions between groups, the
configuration supports multiple conversions. Instead of using the simple key
value pair in the above example, you need the following structure:

```yaml
rename_user:
  default: <template>
  groups:
    group_A: <template>
    group_B: <template>
```

In this example, the `default` key is optional. It is used as fallback in case
there are more that the defined groups in SRAM then are specified in the
configuration file, i.e. `group_A` and `group_B` in the example. If there would
a group `group_C`, the default values will be used instead. An error will be
issued when the template for a group can not be determined from the
configuration file.

The same variables are accepted as in the single line declaration from above.

#### groups

The group block specifies what groups need to be synced from SRAM. You must
use the short names for groups in SRAM as this is how SRAM CO groups appear
in the SRAM LDAP. This does not mean that they must appear with the same
name in the destination LDAP. In order to specify its destination name, you
must use the `destination:` key.

The `EventHandler` might need some additional information. These are called
attributes in the configuration and are a list (array) of strings to be passed
along to the `EventHandler` object. The values of these strings are
meant to be interpreted by the EventHandler class and are meaningless to the
main loop.

Lets assume the short name of the CO group to be synchronized is:
'experiment_A' and that we would like to call it 'sram_experiment_a' at the
destination. The specification for a group could be as follows:

```yaml
sync:
  groups:
    expermiment_A:
       attributes: ["attibute_1", "attibute_2", "attibute_3"]
       destination: sram_experiment_a
```

The number of groups is unlimited. The following variables are supported in
the template:

| variable    | description                                     |
|-------------|-------------------------------------------------|
| `{service}` | Service name defined in the configuration file. |
| `{org}`     | Organisation name in SRAM.                      |
| `{co}`      | CO name in SRAM.                                |

For example:

```yaml
sync:
  groups:
    expermiment_A:
       attributes: ["attibute_1", "attibute_2", "attibute_3"]
       destination: sram-{org}-{co}-experiment_a
```

#### Mapping a group to multiple destinations

If you need to map a single group in SRAM to multiple groups at your service,
then you can use a list of names, instead of a string. The following demonstrates
a configuration example:

```yaml
sync:
  groups:
    expermiment_A:
       attributes:
         - "attibute_1"
         - "attibute_2"
         - "attibute_3"
       destination:
         - "sram-{org}-{co}-experiment_a"
         - "sram-{org}-{co}-extra-group"
```

Also note in the above example, that the attributes are still listed as a YAML
list. This is no different from the previous two examples. Just a different
notation within YAML. Use which ever you prefer.

#### Predefined attributes

The previous sub section stated that the attributes are meaningless to the main
loop. There are, however, two exceptions: `login_users`, `grace_period`. All
users within a CO are also available in the `@all` entry. A service might wish
for a more fine grained control on what users are allowed access. For this
purpose any group can be marked `login_users` through the attributes. This tells
`sync-with-sram` that it should not use the implicit `@all` group, but rather
the groups with this attribute. This means that `sync-with-sram` will only use
those groups for adding users. In case there are no groups with such an
attribute, the main loop will use the `@all` instead.

The `grace_period` attribute tells `sync-with-sram` that for this particular
group a grace period must be applied. Normally `sync-with-sram` would emit a
removal event when it detects that a user is no-longer present in a group.
This would then trigger an immediate removal of that users. The grace key
allows for a delay by specifying for which groups a grace period exists and
the length of this period.

The grace period is specified in the attribute itself. The format of the
`grace_period` is: `grace_period=<period>`. The `<period>` is the time frame
for which the grace period is in effect. Allowed time specification are:

| Period                                     | Comment          |
|--------------------------------------------|------------------|
| \<Rational number\>                        | days             |
| \<Rational number\>d                       | days             |
| \<Rational number\>m                       | months (30 days) |
| \<Rational number\>H                       | hours            |
| \<Rational number\>M                       | minutes          |
| \<Rational number\>s                       | seconds          |
| \<days\>:\<hours\>:\<minutes\>:\<seconds\> | days:HH:MM:SS    |
| \<hours\>:\<minutes\>:\<seconds\>          | HH:MM:SS         |
| \<hours\>:\<minutes\>                      | HH:MM            |

The rational numbers (ℚ) are limited to positive numbers. One cannot specify
-1H for example. When using the time format (HH:MM:SS), only the 24h notation
is suppored, not AM/PM. Always use twi digits for: \<hours\>, \<minutes\> and
\<seconds\>. If no unit is used (d, m, H, M, or s), d (days) is assumed.

In case you want to ignore a defined group in the configuration file, you could
use the `ignore` attribute. When `sync-with-sram` encounters this attribute, it
will completely ignores its existence and continues as though the group was never
defined.

#### event_handler

The `event_handler:` key takes an array of two keys: `name:` and `config:`. The
`name:` key specifies the class name of which an instance must be created at
run time, while the `config:` key, which is optional, specifies a YAMLg
configuration that needs to be passed on to the instantiated class. The main
loop is unconcerned with this configuration and ignores its structure. The
instantiated class however could check for its validity. The specification for
`event_handler` is as follows:

```yaml
sync:
  event_handler:
    - name: <class name>
      config:
        ...
        ...
    - name: <class name>
      config:
        ...
        ...
```

The `config:` in the above is optional.

## Keeping track of the current state

The main loop must know the state of the destination in order to determine the
delta between the destination and SRAM. In order to do so a generic `State`
class is defined with a predefined API. The SRAMsync provides a simple json
back end to keep track of the current state. This is the `JsonFile` class. To
use this class you need to add the following for the `status:` block:

```yaml
status:
  name: JsonFile
  config:
  status_filename: <path to state file>
  provisional_status_filename: <path to provisional state file>
```

Both `status_filename` and `provisional_status_filename` are filenames where
`sync-with-sram` keeps track of the current state. The `status_filename` is
read at the beginning so that `sync-with-sram` can determine the state of the
last sync. `provisional_status_filename` is optional. If you do use it,
`sync-with-sram` will write its status info to that file instead and not
`status_filename`. It is expected that the instantiated EventHandler object
copies the `provisional_status_filename` to `status_filename`. If the
instantiated object fails to do so, `sync-with-sram` will always see new events
as the `status_filename` is never updated to the latest sync state.

## Putting it together

In order to get a valid configuration, we need to put together all the needed
elements. Thus a valid configuration should look like this:

```yaml
service: my_service
secrets:
  file: <path to secrets file>
sram:
  uri: ldaps://ldap.sram.surf.nl
  basedn: dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  binddn: cn=admin,dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  passwd_from_secrets: true
sync:
  users:
    aup_enforcement: true
    rename_user:
      default: "sram-{co}-{uid}"
      groups:
        expermiment_A: "{service}-{uid}"
  groups:
    expermiment_A:
       attributes: ["login_users", "grace_period=90d", "attibute_1", "attibute_2"]
       destination: sram_experiment_a
    expermiment_B:
       attributes: ["login_users", "attibute_3"]
       destination: sram_experiment_b
    expermiment_C:
       attributes: ["attibute_1"]
       destination: sram_experiment_b
  event_handler:
    name: DummyEventHandler
status:
  name: JsonFile
  config:
    status_filename: status.json
    provisional_status_filename: provisional-status.json
```

In the above we see that two groups are synchronized: expermiment_A and
expermiment_B. A DummyEventHandler class is used to deal with the emitted
events from the main loop. In case of the DummyEventHandler nothing is done
except printing info messages to stdout. It does not take any additional
configuration and therefor the `config:` key is omitted.

### Notes for the above example

**Note 1**

In the above `sram` block,

```yaml
passwd_from_secrets: true
```

can be substituted by:

```yaml
passwd: <password>
```

**Note 2**

Even though either keyword `passwd_from_secrets` or `passwd`
can be specified, if the environment variable `SRAM_LDAP_PASSWD` is
defined, it takes precedence over either key word.

**Note 3**

If for all users the same conversion applies, the `rename_user` block can be
written as:

```yaml
sync:
  users:
    rename_user: "sram-{co}-{uid}"
```

## Variable substitution

The configuration has support for variable substitution. This means that
certain keywords between curly brackets are substituted by their value. For
example, the configuration allows for defining the service name with the
`service:` key. When defining destination names for groups, the `{service}`
variable can be used and is replaced by the key value at run time. Given the
following configuration snippet:

```yaml
service: compute
sync:
  groups:
    login_users:
      destination: "{service}-login_users"
```

The `{service}` variable is replace by `compute` and the following snippet is
equal to the previous one:

```yaml
service: compute
sync:
  groups:
    login_users:
      destination: "compute-login_users"
```

In case you need to sync multiple services, you could also use the `{service}`
variable for the `status_filename` and `provisional_status_filename` to easily
distinguish status files for different services.

### Available variables

The following variables are available:

| Config Item                       | Tags                         |
|-----------------------------------|------------------------------|
| status_filename                   | `{service}`                  |
| provisional_status_filename       | `{service}`                  |
| mail_subject                      | `{service}`                  |
| mail_message                      | `{service}`                  |
| sync/users/rename_user            | `{co}`, `{uid}`              |
| sync/groups/\<group\>/destination | `{service}`, `{org}`, `{co}` |

## Removal of the status file

When the status file is removed, it effectively means that all SRAM LDAP
entries appear as new and thus each entry will be up for synchronization.
Weather this is a problem or not depends on the EventHandler and how it deals
with wiping graced users. Remember that the status file keeps track of graced
users and by deleting the status file this information is lost. This means that
for graced users `sync-with-sram` will never be able to detect when a grace
user must be removed. Effectively graced users will continue to exits until
removed manually.

## Logging

SRAMsync supports different log levels: CRITICAL, ERROR, WARNING, INFO and
DEBUG. The default level is set to ERROR and can be changed by the `--loglevel
<level>` option or its short hand equivalent `-l`. One could also switch on
debug logging quickly, by selecting either `--debug` or `-d`. The `--verbose`
option increase the log level once each time selected and can be used multiple
times.

## EventHandler Classes

The main loop of SRAMsync, reads out the SRAM LDAP and based on what it reads
and what it knows about the destination state, it determines what needs to be
done in order to synchronize the destination. It could be that a new user has
been found, or that a user has been removed from a group in SRAM. These
differences between SRAM and the destination are detected and the main loop
triggers an event for each of these occurrences.

EventHandlers are dynamically loaded and hence you can write your own
EventHandler and use it with SRAMsync. A few EventHandler classes are
available from the SRAMsync package. Each has its own configuration and can be
selected in the configuration file by simply specifying the name of the
EventHandler in the `name` property. In case you would like to create your own
EventHandler, you must use the full module name, i.e. `<module>.<class>`.

For creating your own custom EventHandler implementation see [below](#creating-a-custom-eventhandler).

### DummyEventandler

This the most basic implementation of an EventHandler class. All it does is
print an informative message, which shows up when the loglevel is set to DEBUG.

A configuration could be passed at creation time and it will be printed out
for the DEBUG level.

### CuaScriptGenerator

The purpose of the `CuaScriptGenerator` is for the SURF LDAP, called CUA. In
order to interact with the CUA, a set of commandline tools have been developed
over the years. These are known as `sara_usertools`. Two commands are provided:
`sara_adduser` and `sara_modifyuser`. These commands do the heavy lifting one
normally needs to do with `ldapsearch`, `ldapadd` and `ldapmodify` commands. By
providing these tools the CUA is shielded from incorrect usages of the low level
LDAP commands.

The `CuaScriptGenerator` generates a bash script composed of `sara_usertools`
commands. Execution of the generated bash script brings the CUA in line with
SRAM. Since `sync-with-sram` cannot learn what the current state of the CUA
is, a status file is generated upon each synchronization run. Theoretically
the execution of the generated bash might fail at any point and the status
of the CUA might be in some state between the original state at the beginning
of the synchronization and the desired end goal. In order to guard against
this situation, the status file is not created immediately. Instead a
provisional status file is generated. It is up to the generated bash script
to update the status file with the provisional one once the bash script
reaches the end of its execution.

If the status file is not replaced by the provisional one, SRAMsync will
generate the same bash script again. Thus a replay of already executed commands
cannot be avoided. It is thus relied upon that the `sara_usertools` is robust
against these kinds of replays.

The `CuaScriptGenerator` makes use of any additional `EventHandler` class in
`auxiliary_event_handler`. This could be for example the `EmailNotifications`
class for mailing events.

#### CuaScriptGenerator configuration

The `CuaScriptGenerator` class needs to know a few things in order to be able
to generate a bash script based on the `sara_usertools`. First of all, there is
the name of the generated script. This is specified by: `filename:`. Then there
are the three commands for adding, modifying and checking groups and users:
`add_cmd:`, `modify_cmd:`, `check_cmd` and `sshkey_cmd`. All commands can be
prefixed with `sudo` and can be extended with options, e.g. `sudo sara_adduser
--no-usermail`. This string will be inserted literally into the bash script
when `sara_adduser` is needed. The `check_cmd` is used prior to adding
users or groups to determine if the user or group already exists. Adding and
removing public SSH keys is done through the `sshkey_cmd`.

The final key that the `CuaScriptGenerator` understands, but does not require,
is `auxiliary_event_handler:` Any `EventHandler` class can be given here. If
specified, the `CuaScriptGenerator` will as part of its own processing of the
emitted events, call for the same events of the `auxiliary_event_handler`. This
way it is for example possible to not only generate a bash script but also
mail notifications as they happen.

The following is the configuration for the `CuaScriptGenerator` class:

```yaml
sync:
  event_handler:
    - name: CuaScriptGenerator
      config:
        filename: <filename>
        add_cmd: sudo sara_adduser --no-usermail
        modify_cmd: sudo sara_modifyuser --no-usermail
        check_cmd: sudo sara_modifyuser --no-usermail --check
        sshkey_cmd: sudo sara_modifyuser --no-usermail --ssh-public-key
  ```

### CbaScriptGenerator

The CbaScriptGenerator is derived from the CuaScriptGenerator class.
Therefore the CbaScriptGenerator cannot be used independently from the
CuaScriptGenerator. This means that if you use this class, you will need to
provide a configuration for the CuaScriptGenerator class as well.

The purpose of the CbaScriptGenerator class is to enhance the generated bash
script of the CuaScriptGenerator class. When a user gets added and CBS
accounting is needed, this class injects the appropriate command for this. The
same holds true for removing a user. The resulting bash script needs to be
executed in order for the generated command to take affect.

#### CbaScriptGenerator configuration

The CbaScriptGenerator class introduced the following configuration:

```yaml
sync:
  event_handler:
    - name: CbaScriptGenerator
      config:
        cba_add_cmd: <CBA command for adding a user>
        cba_del_cmd: <CBA command for deleting a user>
        cba_machine: <CBA machine name>
        cba_budget_account: <CBA budget account>
  ```

When using the CbaScriptGenerator class, four required configuration
fields must be present: `cba_add_cmd`, `cba_del_cmd`, `cba_machine` and
`cba_budget_account`. The fifth, `cua_config` is also required and marks the
start of the CUA configuration. Please refer to
[CuaScriptGenerator](#CuaScriptGenerator) for additional information on the
CuaScriptGenerator class and how it is configured. Note that what follows
the `config` CuaScriptGenerator class should follow the `cua_config` for the
CbaScriptGenerator configuration.

### EmailNotifications

If you want to be informed by email about any of the emitted events during the
execution of the main loop, the `EmailNotifications` class does that. It
connects to an SMTP server and sends customizable emails through it. Events can
be grouped, so you don't have tp receive a separate email for each emitted
event. However, this event handler can be setup in such a way that you can receive
an email for each event. In case you want to collect email on a per CO basis, that
is also possible.

In the configuration of the `EmailNotifications` class you can specify for
which events you would like to be notified. For each notification you can
configure the line that needs to be generated and optionally a header that is
used for that event. The header is optional. In other words, each event takes
the form of:

```yaml
report_events:
  <event>:
    header: <header line>
    line: <event line>
```

In order to connect to an SMTP server, the following configuration keys are
available:

```yaml
smtp:
  host: <SMTP host>
  port: <SMTP port number>
  login: <SMTP login name>
  passwd_from_secrets: <boolean>
```

In case you don't use the secrets files, you must use `passwd: <secret>`
instead and expose your SMTP password in the configuration file.

For composing email messages, the configuration supports the following keys:

```yaml
  mail-to: <mail recipiant>
  mail-from: <who is sending the email>
  mail-subject: <mail subject>
  mail-message: <mail message body>
```

The `mail-message:` in your configuration should contain `{message}` at a
minimum.  If it is missing no text will appear in your message. This variable
is replaced by the headers and lines of the events. The `{message}` text can
be part of a more descriptive text.

#### EmailNotifications configuration

Below is an example of the configuration part for the `EmailNotifications`
event handler.

```yaml
sync:
  event_handler:
  - name: EmailNotifications
    config:
      collect_events: <boolean>
      aggregate_mails: <boolean>
      report_events:
        start-co-processing:
          header: <start header>
          line: <start line>
        add-new-user:
          header: <add-new-user header>
          line: <add-new-user line>
        add-ssh-key:
          header: <add-ssh-key header>
          line: <add-ssh-key line>
        delete-ssh-key:
          header: <delete-ssh-key header>
          line: <delete-ssh-key line>
        add-group:
          header: <add-group header>
          line: <add-group line>
        remove-group:
          header: <remove-group header>
          line: <remove-group line>
        add-user-to-group:
          header: <add-user-to-group header>
          line: <add-user-to-group line>
        remove-user-from-group:
          header: <remove-user-from-group header>
          line: <remove-user-from-group line>
        remove-graced-user-from-group:
          header: <remove-graced-user-from-group header>
          line: <remove-graced-user-from-group line>
        finalize:
          header: <finalize header>
          line: <finalize line>
        smtp:
          host: <SMTP host>
          port: <SMTP port number>
          login: <SMTP login name>
          passwd: <SMTP password>
        mail-to: <mail recipiant>
        mail-from: <who is sending the email>
        mail-subject: <mail subject>
        mail-message: <mail message body>
```

For available variables in formatting headers and lines, please also refer to
[Variable substitution](#variable-substitution) and [Events](#events). The italic
keywords in the Event section are available as variables for both `header:` and
`line:` keys.

```yaml
event_handler:
  name: EmailNotifications
    config:
      collect_events: true
      aggregate_mails: true
      report_events:
        add-new-user:
          header: "Adding the following users:"
          line: "Add new user {user}"
```

Bother the `collect_events` and `aggregate_mails` are optional and when left
out defaults to `true`, in which case a single mail will be sent for the entire
synchronization run. In this e-mail all events are grouped per CO. If
`aggregate_mails` is set to `false` and `collect_events` is set to `true`, a
mail for each CO is generated. In case you want to get an email for each event,
set `collect_events` to `false` and don't include `aggregate_mails`. When mails
are aggregated and there are no important events to be reported, i.e. events
other that `start-co-processing` and `finalize` the e-mail sending is
repressed.

#### Supported command line options

The `EmailNotifications` supports sending mails to the `stdout` instead of
using the SMTP server. In order to use this feature, the `EmailNotifications`
supports the `--eventhandler_args` with at least `mail-to-stdout` specified.
Call `sync-with-sram` like this for example:

```bash
sync-with-sram --log-level=info --eventhandler-args mail-to-stdout <config file>
```

### Creating a custom EventHandler

Alternatively one can also specify their own EventHandler class by setting the
`name` property to the exact package & module name of the class.

Assume we have the following EventHandler in the file `my_event_handler.py`
in the folder `my_package`:

```python
from SRAMsync.event_handler import EventHandler

class MyEventHandler(EventHandler):
  <implementation of all abstract methods>
```

Then the `event_handler` property needs to be set to:

```yaml
sync:
  <other sync parameters ...>
  event_handler:
    - name: my_package.my_event_handler.MyEventHandler
      config:
        <MyEventHandlerConfig (optional)>
```

The sources only need to be visible via `PYTHONPATH`:

```bash
export PYTHONPATH=/path/to/source/:$PYTHONPATH
sync-with-sram -d path/to/config.yaml
```

## Events

SRAMsync defines the following events and their variables:

* **start-co-processing:** *co*
* **add-new-user:** *co, group, givenname, sn, user, mail*
* **add-public-ssh_key:** *co, user, key*
* **delete-public-ssh-key:** *co, user, key*
* **add-new-group:** *co, group, attributes*
* **remove-group:** *co, group, attributes*
* **add-user-to-group:** *co, group, user, attributes*
* **start-grace-period-for-user:** *co, group, attributes, user, duration*
* **remove-graced-user-from-group:** *co, group, user, attributes*
* **remove-user-from_group:** *co, group, user, attributes*
* **finalize**

In fact, the above defined events are from the abstract base class found in the
`EventHandler` class. In case you wish to create your own EventHandler,
you should derive such class from the `EventHandler` abstract base class.

### When are events emitted

Event are emitted from the main loop of `sync-with-sram`. Some event are always
emitted at the appropriate moment like: `start-co-processing` and `finalize`.
The emitting of other events depends on the current state of SRAM LDAP and the
destination. If there are no differences no events will be emitted.

#### start-co-processing

| Input | Description |
|:------|:------------|
| co    | CO name for which the synchronization has started.|

Emitted at the beginning and before any other event. This is to signal that the
synchronization process has started for CO `co` and is always emitted.

#### add-new-user

| Input     | Description |
|:----------|:------------|
| co        | CO name for which the event was emitted.          |
| group     | Group to which the user needs to be added.        |
| givenname | First name of the user as it is known to SRAM.    |
| sn        | Last name of the user as it is known to SRAM.     |
| user      | User name of the user at the destination.         |
| mail      | E-mail address of the user as it is known to SRAM.|

When a new user is detected in the SRAM LDAP, this event will be emitted for
each new users that is part of a `login_group` or the `@all` reserved group
which holds all CO members by default. See [group](#groups) for more details on
`login_group` and how to define one.

#### add-public-ssh-key

| Input | Description |
|:------|:------------|
| co    | CO name for which the event was emitted.   |
| user  | User name as it is used on the destination.|
| key   | Public SSH key of the user.|

When a user adds a new public SSH key to its profile in SRAM, this event will
be emitted. Note that an update of an SSH key will not be detected as a change,
but rather as removal of an old key and adding a new key instead.

#### delete-public-ssh-key

| Input | Description |
|:------|:------------|
| co    | CO name for which the event was emitted.    |
| user  | User name as it is used on the destination. |
| key   | Public SSH key of the user|

When a users deletes a public SSH key in its profile in SRAM, this event will
be emitted. Note that an update of an SSH key will not be detected as a change,
but rather as removal of an old key and adding a new key instead.

#### add-new-group

| Input      | Description |
|:-----------|:------------|
| co         | CO name for which the event was emitted. |
| group      | Name of the group that exists in SRAM but not yet at the destination.|
| attributes | List of attributes as specified for the group in the `sync-with-sram` configuration file.|

When a new group appears in the SRAM LDAP for for the current CO, this event
will be emitted. The attributes from the configuration file are sent along for
possible further processing.

#### remove-group

| Input      | Description |
|:-----------|:------------|
| co         | CO name for which the event was emitted. |
| group      | Name of the group that exists in SRAM but not yet at the destination.|
| attributes | List of attributes as specified for the group in the `sync-with-sram` configuration file.|

When a group is removed in the SRAM LDAP for for the current CO, this event
will be emitted. The attributes from the configuration file are sent along for
possible further processing.

#### add-user-to-group

| Input     | Description |
|:----------|:------------|
| co        | CO name for which the event was emitted. |
| group     | Name of the group that exists in SRAM but not yet at the destination.|
| user      | User name of the user at the destination.|
| attributes| List of attributes as specified for the group in the `sync-with-sram` configuration file.|

When in SRAM a user is added to a group, this event will be emitted. This is
different from the `add_new_user` event as that one is emitted for
`login_group`s and this one for all other groups. In other words, the `user` is
already provisioned at the destination, but not yet added to the `group`.

#### start-grace-period-for-user

| Input     | Description |
|:----------|:------------|
| co        | CO name for which the event was emitted. |
| group     | Name of the group that exists in SRAM but not yet at the destination.|
| attributes| List of attributes as specified for the group in the `sync-with-sram` configuration file.|
| user      | User name of the user at the destination.|
| duration  | Length of grace period in days. |

When a `user` is removed from a `group`, this event will be emitted in case the
`grace_preriod` was set in the group attributes list. If the `grace_preriod`
attribute was not set, the `remove-user-from-group` event will be emitted
instead. The user should not be removed during the grace period. When the
`grace_preriod` has ended, the `remove-graced-user-from-group` is emitted to
signal that the `user` must be removed.

#### remove-graced-user-from-group

| Input     | Description |
|:----------|:------------|
| co        | CO name for which the event was emitted. |
| group     | Name of the group that exists in SRAM but not yet at the destination.|
| user      | User name of the user at the destination.|
| attributes| List of attributes as specified for the group in the `sync-with-sram` configuration file.|

When a `user` has been removed from a `group`, for which the `grace_period`
attribute was set, and the grace period of the user has passed, this event will
be emitted. This also means that `sync-with-sram` will permanently remove this user from
the group.

#### remove-user-from-group

| Input     | Description |
|:----------|:------------|
| co        | CO name for which the event was emitted. |
| group     | Name of the group that exists in SRAM but not yet at the destination.|
| user      | User name of the user at the destination.|
| attributes| List of attributes as specified for the group in the `sync-with-sram` configuration file.|

When a `user` is removed from a `group`, this event will be emitted. However,
if the `group` has the `grace_period` attribute set, the user will not be
removed until the grace period has ended. This event will be emitted non the
less that the user has been removed from the group.

#### finalize

Input: *none*

This is the very last event to be emitted. It signals that the synchronization has
finished and is always emitted

## Acknowledgment

This project has received funding from the European Union’s Horizon 2020 research and innovation programme under grant agreement No 101017529.
