# Behave scenarios

## Add a member to a login group

<span style="color:gray">File:</span> `add_login_user.feature`

Add a new user to a group for which the `login_users` attribute has
been set.

```text
Organisation: Rivendell
          CO: Fellowship
       Group: shirecloud_login
      Member: eowyn
```

## Remove a user from group with a grace period

<span style="color:gray">File:</span> `remove_user_with_grace.feature`

Remove a user from a group for which the `grace_period` has been set.

```text
Organisation: Rivendell
          CO: Fellowship
       Group: -
      Member: samwise
```

## Add and remove SSH keys

```text
Organisation: Rivendell
          CO: Fellowship
       Group: -
      Member: samwise
```

<span style="color:gray">File:</span> `ssh_key_management.feature`

Add and remove an SSH key for user samwise. First make sure that the
test key is not present. Then add it to LDAP and check if event for
adding a new SSH key is discovered, i.e. is the event name found on
stdout.

```text
Organisation: Rivendell
          CO: Fellowship
       Group: -
      Member: samwise
```

## Remove entire group

<span style="color:gray">File:</span> `ssh_key_management.feature`

Removing a group means removing all members as well. The grace period
must be respected if set.

```text
Organisation: Hogwarts
          CO: Griffindor
       Group: wizardry_owl
      Member: all
```
