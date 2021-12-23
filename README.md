# SRAMsync

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-ble.svg)](http://perso.crans.org/besson/LICENSE.html)

## Purpose of SRAMsync

SRAMsync is an LDAP to LDAP synchronization script written in Python.
Originally it was developed for synchronization between
[SRAM](https://sbs.sram.surf.nl) and an LDAP at SURF, such that different SURF
Research services would be able to obtain user attributes and grant users
access to the services. The first versions were tailored towards the specifics
needed by SURF, version 2 takes things a little further and generalizes a few
pieces a bit more such that its applicability is extended.

## Installation

The SRAMsync package can be installed by pip. Use the following the install
the latest from the *main* branch on GitHub:

```bash
pip install git+https://github.com/venekamp/SRAMsync.git#egg=SRAMsync
```

If you wish to use a specific version you should use the following:

```bash
pip install git+https://github.com/venekamp/SRAMsync.git@v2.0.0#egg=SRAMsync
```

The exact versions, i.e. the  *@v2.0.0* in the above url, can be found the
[tags page](https://github.com/venekamp/SRAMsync/tags) at GitHub.

## Invocation

The SRAMsync package contains an executable called: `sync-with-sram`. It takes
a single argument and options. This argument is a YAML configuration file that
tells where to find the LDAP to sync from, baseDN, bindDN and password. The
configuration file also tell what groups need to be synced and what they will
be called in the destination LDAP.

## Structure of sync-with-sram

The `sync-with-sram` consists out of a main loop that itterates over the SRAM
LDAP as defined per configuration. The main loop does not do anything more than
this itteration. For example, it does not write entries into a destination
LDAP. In fact, the main loop in unaware what it should do with all encountered
entries. All it does is emitting events when some action could be required.
Events are triggered when for example the main loop detects that a new user is
added to SRAM. Now it is up to whoever is responsible for dealing with such an
event and what it really means. In case of a new user this should ultimately
end with a user being added to some destination LDAP, but it is not the
responsibility of the main loop. Instead the configuration requires an
`EventHandler` class to be instantiated.

A design choice was to dynamically load derived `EventHandler` classes. Thereby
allowing for multiple implementations of emitted events. This allows for
flexibility such that `sync-with-sram` can be invoked for any number of
environments which need to synchronize SRAM LDAP attributes. Although,
`sync-with-sram` started out as an LDAP to LDAP synchronization process, given
its design the destination end does not need to be an LDAP. It is up to an
`EventHandler` class to decide what needs to be done.

## Events

SRAMsync defines the following events and their variables:

* start_of_service_processing: *co*
* add_new_user: *group, givenname, sn, user, mail*
* add_public_ssh_key: *user, key*
* delete_public_ssh_key: *user, key*
* add_new_group: *group, attributes*
* remove_group: *group, attributes*
* add_user_to_group: *group, user, attributes*
* remove_user_from_group: *group, user, attributes*
* remove_graced_user_from_group: *group, user, attributes*
* finalize

In fact, the above defined events are from the abstract base class found in the
`EventHandler` class. In case you wish to create your own  EventHandler,
you should derive such class from the `EventHandler` abstract base class.

## Tags and substitution

TODO:

## Configuration details

The executable `sync-with-sram` needs a configuration file in order to know
what and how to sync. The configuration is done in YAML. At the highest level
the configuration looks as follows:

```yaml
service: <service name>
sram:
   <connection details>
sync:
   <synchronization details>
status_filename: <file name>
provisional_status_filename: <file name>
```

As can be noticed from the above, two major blocks can be identified.

1. `sram:` Connection details for SRAM
2. `sync:` What and how to synchronize

The `service` key is for specifying the name of the local service. Both
`status_filename` and `provisional_status_filename` are file names where
`sync-with-sram` keeps track of the current state. These two keys are used for
keeping track of the current state of the synchronization process.

### SRAM connection details

The script needs to know how it should connect to the SRAM LDAP. As a service
you are allowed to read, not write, to a subtree in LDAP that has been created
for your service. You should have been given a base DN and accompanying bind DN
and passwd. The full specification of the `sram:` key is as follows:

```yaml
sram:
  uri: ldaps://ldap.sram.surf.nl
  basedn: dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  binddn: cn=admin,dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  passwd: <your password>
```

### Synchronization details

The `sync:` holds all information regarding what to sync and in which way
to do it. Within this key there are three blocks: `groups:`, `event_handler:`
and `grace:`. Thus on a high level, the `sync:` block look like this:

```yaml
sync:
  groups:
    <group synchronization information>
  event_handler:
    name: <event handler class name to instantiate>
    config:
      <configuration for instantiated EventHandler class>
  grace:
    <group names for which to apply a grace period>:
      grace_period: <grace period in days>
```

#### groups

The group block specifies what groups need to be synced from SRAM. You must
use the short names for groups in SRAM as this is how SRAM CO groups appear
in the SRAM LDAP. This does not mean that thay must appear with the same
name in the destination LDAP. In order to specify its destination name, you
must use the `destination:` key.

The `EventHandler` might need some additional information. These are called
attributes in the configuration and are a list (array) of strings to be passed
along to the `EventHandler` instantiation. The values of these strings are
meant to be interpreted by the instantiated class and are meaningless to the
main loop.

Lets assume the short name of the CO group to be synchronized is:
'experiment_A' and that we would like to call it 'sram_experiment_a' at the
destination. The specification for a group is as follows:

```yaml
sync:
  groups:
    expermiment_A:
       attributes: ["attibute_1", "attibute_2", "attibute_3"]
       destination: sram_experiment_a
```

The number of groups is unlimited.

#### event_handler

The `event_handler:` key takes two keys: `name:` and `config:`. The `name:` key
specifies the class name of which an instance must be created at run time,
while the `config:` key specifies a YAML configuration that needs to be passed
on to the instantiation class. The main loop is unconcerned with this
configuration and ignores its structure. The instantiated class however could
check for its validity. The specification for `event_handler` is as follows:

```yaml
sync:
  event_handler:
    name: <class name>
    config:
       ...
       ...
```

#### grace

The grace key is used when the removal of users should not take place
immediately, but should be effectuated after a grace period. Noramlly
`sync-with-sram` would emit a removal event when it detects that a user is
no-longer present in a group. This would then trigger an immediate removal of
that users. The grace key allows for a delay by specifying for which groups a
grace period exists and the length of this period.

The grace key lists the short names for groups in SRAM for which you want to
use a grace period and then you specify the period in the number of days. The
specification for grace is as follows:

```yaml
sync:
  grace:
    expermiment_A:
      grace_period: 90
```

## Putting it together

In order to get a valid configuration, we need to put together all the needed
elements. Thus a valid configuration should look like this:

```yaml
sram:
  uri: ldaps://ldap.sram.surf.nl
  basedn: dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  binddn: cn=admin,dc=<service short name>,dc=services,dc=sram,dc=surf,dc=nl
  passwd: <your password>
sync:
  groups:
    expermiment_A:
       attributes: ["attibute_1", "attibute_2", "attibute_3"]
       destination: sram_experiment_a
    expermiment_B:
       attributes: ["attibute_4"]
       destination: sram_experiment_b
  event_handler:
    name: DummyEventHandler
  grace:
    expermiment_A:
      grace_period: 90
status_filename: status.json
provisional_status_filename: provisional-status.json
```

In the above we see that two groups are synchronized: expermiment_A and
expermiment_B. A DummyEventHandler class is used to deal the emitted events
from the main loop. In case of the DummyEventHandler nothing is done except
printing debug messages to stdout.

## Removal of the status file

TODO:

## Logging

SRAMsync supports different log levels: CRITICAL, ERROR, WARNING, INFO and
DEBUG. The default level is set to ERROR and can be changed by the `--loglevel
\<level>` option or its short hand equivalent `-l`. One could also switch on
debug logging quickly, by selecting either `--debug` or `-d`. The `--verbose`
option increase the log level once each time selected and can be used multiple
times.

## EventHandler Classes

A few EventHandler classes are available. Each has its own configuration and
can be selected in the configuration file.

### DummyEventandler

This the most basic implementation of an EventHandler class. All is does is
print an informative message, which shows up when the loglevel is set to DEBUG.

A configuration could be passed at creation time and it will be printed out
for the DEBUG level.

### CuaScriptGenerator

The purpose of the `CuaScriptGenerator` is for the SURF LDAP, called CUA. In
order to interact with the CUA, a set of command line tools have been developed
over the years. These are known as `sara_usertools`. Two commands are provided:
`sara_adduser` and `sara_modifyuser`. These commands do the heavy lifting one
normally needs to do with `ldapsearch`, `ldapadd` and `ldapmodify` commands. By
providing these tools the CUA is shielded by incorrect usages of the low level
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
to update the status file with the provisional one once all bash script
reaches the end of its execution.

If the status file is not replaced by the provisional one, SRAMsync will
generate the same bash script again. Thus a replay of already executed commands
cannot be avoided. It is thus replied upon that the `sara_usertools` is robust
against these kinds of replays.

The `CuaScriptGenerator` makes use of any additional `EventHandler` class. This
could be for example the `EmailNotifications` class for mailing events.

#### configuration

The `CuaScriptGenerator` class needs to know a few things in order to be able
to generate a bash script based on the `sara_usertools`. First of all, there is
the name of the generated script. This is specified by: `filename:`. Then there
are the two commands for adding and modifying groups and users: `add_user_cmd:`
and `modify_user_cmd:`. Both can be prefixed with `sudo` and can be extended
with options, e.g. `sudo sara_adduser --no-usermail`. This string will be
inserted literally into the bash script when `sara_adduser` is needed.

The final key that the `CuaScriptGenerator` understands, but does not require,
is `auxiliary_event_handler:` Any `EventHandler` class can be given here. If
specified, the `CuaScriptGenerator` will as part of its own processing of the
emitted events, call for the same events of the `auxiliary_event_handler`. This
way it is for example possible to not only generate a bash script but also
mail notifications as they happen.

The following is the configuration for the `CuaScriptGenerator` class:

```yaml
sync:
  event_handler: CuaScriptGenerator
  config:
    filename: <filename>
    add_user_cmd: sudo sara_adduser --no-usermail
    modify_user_cmd: sudo sara_modifyuser --no-usermail
    auxiliary_event_handler:
      name: EmailNotifications
      config:
        <EmailNotifications configuration>
```

### EmailNotifications

If you want to be informed by email about any of the emitted events during the
execution of the main loop, the `EmailNotifications` class does that. It
connects to an SMTP server and sends customizable email through it. Events are
conveniently grouped so you don't receive a separate email for each emitted
event. That would add up real quickly. Instead all events for a CO are
collected first and once the main loop has finished processing the CO, all
queued messages are collected in a single email. In the configuration of the
`EmailNotifications` class you can specify for which events you would like to
be notified. For each notification you can configure the line that needs to be
generated and optionally a header that is used for that event. In other words,
each event takes the form of:

```yaml
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
  passwd: <SMTP password>
```

For composing email messages, the configuration supports the following keys:

```yaml
  mail-to: <mail recipiant>
  mail-from: <who is sending the email>
  mail-subject: <mail subject>
  mail-message: <mail message body>
```

The `mail-message:` should contain at a minimum the following text `{message}`,
if you want the headers and lines from the event to appear in mail. This tag is
replaced by the headers and lines of the events.

#### configuration

```yaml
sync:
  event_handler: EmailNotifications
  config:
    report_events:
      start:
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

For available tags in formatting headers and lines, please also refer to
[tags and substitution](#tags-and-substitution)
