"""ldap helper functions"""
import copy
import json
import random

import ldap
from ldap import modlist

import SRAMsync.config
from SRAMsync.sync_with_sram import init_ldap

BASEDN = "dc=mt-doom,dc=services,dc=sram,dc=surf,dc=nl"


class User:
    def __init__(self, user):
        self.user = user

    def __getitem__(self, item) -> tuple:
        return (item, self.user[item].encode())


class Identities:
    def __init__(self):
        with open("test/data.json") as id_file:
            data = json.load(id_file)
            self.identities = data["identities"]

    def __getitem__(self, item) -> User:
        entry = self.identities[item]

        return User(entry)


def add_user(ldap_conn, org, co, group, uid):
    add_user_flat(ldap_conn, org, co, group, uid)
    add_user_ordered(ldap_conn, org, co, group, uid)


def add_user_flat(ldap_conn, org, co, group, uid):
    """Add new user to LDAP"""
    ldif = get_uid_ldif(uid)

    dn_uid = f"uid={uid},ou=People,dc=flat,{BASEDN}"
    ldap_conn.add_s(dn_uid, ldif)

    # dn = f"cn={org}.{co}.{group},ou=Groups,dc=flat,{BASEDN}"
    dn = f"cn={org}.{co}.{group},ou=Groups,dc=flat,{BASEDN}"
    ldap_conn.modify_s(dn, [(ldap.MOD_ADD, "member", [dn_uid.encode()])])


def add_user_ordered(ldap_conn, org, co, group, uid):
    dn_o = f"o={org}.{co},dc=ordered,{BASEDN}"

    dn_uid = f"uid={uid},ou=People,{dn_o}"
    ldif = get_uid_ldif(uid)

    ldap_conn.add_s(dn_uid, ldif)

    dn_ou = f"cn={group},ou=Groups,{dn_o}"
    # print(dn_ou)
    # dns = context.ldap_conn.search_s(
    #     dn_ou,
    #     ldap.SCOPE_BASE,  # type: ignore pylint: disable=E1101
    #     "(objectClass=*)",
    # )
    # print(dns)
    ldap_conn.modify_s(dn_ou, [(ldap.MOD_ADD, "member", [dn_uid.encode()])])

    dn_ou = f"cn=@all,ou=Groups,{dn_o}"
    ldap_conn.modify_s(dn_ou, [(ldap.MOD_ADD, "member", [dn_uid.encode()])])


def remove_user_from_group(ldap_conn, org, co, group, uid):
    dn_org = f"o={org}.{co},dc=ordered,{BASEDN}"
    dn_group = f"cn={group},ou=Groups,{dn_org}"
    dn_uid = f"uid={uid},ou=People,{dn_org}"

    old_entry = ldap_conn.search_s(dn_group, ldap.SCOPE_BASE, "(objectClass=groupOfMembers)")[0][1]
    new_entry = copy.deepcopy(old_entry)
    new_entry["member"].remove(dn_uid.encode())
    mod_list = ldap.modlist.modifyModlist(old_entry, new_entry)

    ldap_conn.modify_s(dn_group, mod_list)

    return True


def get_uid_ldif(uid):
    identities = Identities()
    user = identities[uid]

    ldif = [
        ("objectClass", [b"top", b"inetOrgPerson", b"eduPerson", b"person", b"voPerson"]),
        ("uid", [f"{uid}".encode()]),
        (user["cn"]),
        (user["sn"]),
        (user["displayName"]),
        (user["eduPersonScopedAffiliation"]),
        (user["givenName"]),
        (user["mail"]),
        (user["voPersonExternalAffiliation"]),
        (user["voPersonExternalID"]),
    ]

    return ldif


def uid_exists(ldap_conn, org, co, uid):
    dn = f"ou=People,o={org}.{co},dc=ordered,{BASEDN}"
    dns = ldap_conn.search_s(dn, ldap.SCOPE_SUBTREE, "(objectClass=person)")

    for entry in dns:
        if entry[1]["uid"][0].decode() == uid:
            return True

    return False


def is_member_of(ldap_conn, org, co, group, uid):
    dn = f"cn={group},ou=Groups,o={org}.{co},dc=ordered,{BASEDN}"
    dn_uid = f"uid={uid},ou=People,o={org}.{co},dc=ordered,{BASEDN}"

    dns = ldap_conn.search_s(dn, ldap.SCOPE_BASE, f"(&(objectClass=groupOfMembers)(member={dn_uid}))")

    return len(dns) > 0


def get_ssh_keys(ldap_conn, org, co, uid):
    dn = f"uid={uid},ou=People,o={org}.{co},dc=ordered,{BASEDN}"
    attributes = ldap_conn.search_s(dn, ldap.SCOPE_SUBTREE, "(objectClass=person)")

    return attributes[0][1]["sshPublicKey"]


def add_ssh_key(ldap_conn, org, co, uid, ssh_key):
    dn = f"uid={uid},ou=People,o={org}.{co},dc=ordered,{BASEDN}"

    if type(ssh_key) != bytes:
        ssh_key = ssh_key.encode()

    old_entry = ldap_conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=person)")[0][1]
    new_entry = copy.deepcopy(old_entry)
    new_entry["sshPublicKey"].append(ssh_key)
    mod_list = ldap.modlist.modifyModlist(old_entry, new_entry)

    ldap_conn.modify_s(dn, mod_list)


def remove_ssh_key(ldap_conn, org, co, uid, ssh_key):
    dn = f"uid={uid},ou=People,o={org}.{co},dc=ordered,{BASEDN}"

    if type(ssh_key) != bytes:
        ssh_key = ssh_key.encode()

    old_entry = ldap_conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=person)")[0][1]
    new_entry = copy.deepcopy(old_entry)
    new_entry["sshPublicKey"].remove(ssh_key)
    mod_list = ldap.modlist.modifyModlist(old_entry, new_entry)

    ldap_conn.modify_s(dn, mod_list)
