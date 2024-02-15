#!/usr/bin/env python3
"""build an SRAM  LDAP"""


import sys
import json
import random
import string
import uuid

import ldap

from SRAMsync.sync_with_sram import init_ldap

DOMAIN = "sram.surf.nl"
FLAT = "flat"
ORDERED = "ordered"

key_comments = [
    "{person}",
    "One Ring to Rule them All",
    "{person}@Middle Earth",
    "LORT - {person}",
]


def generate_ssh_key(person):
    """Generate something that looks like a public SSH key."""
    key_type = "ssh-ed25519"
    pub_key = "".join((random.choice(string.ascii_letters + string.digits) for _ in range(20)))
    comment = random.choice(key_comments)
    comment = f"{comment}".format(**locals())

    return f"{key_type} {pub_key} {comment}"


def generate_eduperson_unique_id():
    """Generate unique ID."""
    id = "".join((random.choice("0123456789abcdef") for _ in range(40)))

    return f"{id}@{DOMAIN}"


def complete_people(people):
    for person, attributes in people.items():
        for key, attr in attributes.items():
            if attr == "?":
                if key == "eduPersonUniqueId":
                    if people[person]["cn"] == "?":
                        people[person][key] = generate_eduperson_unique_id()
                    else:
                        people[person][key] = people[person]["cn"]
                if key == "cn":
                    if people[person]["eduPersonUniqueId"] == "?":
                        people[person][key] = generate_eduperson_unique_id()
                    else:
                        people[person][key] = people[person]["eduPersonUniqueId"]
                if key == "sshPublicKey":
                    people[person][key] = generate_ssh_key(person)


def complete_data(data):
    """Complete data."""
    complete_people(data["people"])
    complete_people(data["identities"])

    for org, org_data in data["groups"].items():
        for co, co_data in org_data["cos"].items():
            for groups, group_data in co_data["groups"].items():
                for k, v in group_data.items():
                    if k == "uniqueIdentifier" and v == "?":
                        group_data[k] = str(uuid.uuid4())


def add_ou_rdn(connection, basedn, rdn):
    """docstring"""
    dn = f"dc={rdn},{basedn}"
    print(f"Building: {dn}")

    ldif = [
        ("objectClass", [b"top", b"dcObject", b"organizationalUnit"]),
        ("dc", [rdn.encode()]),
        ("ou", [rdn.encode()]),
    ]
    connection.add_s(dn, ldif)


def get_ldif_part(key, attributes, alt_key=None):
    if alt_key:
        k = alt_key
    else:
        k = key

    return key, [attributes[k].encode()]


def get_people_ldif(person, attributes):
    """Get people ldif"""
    ldif = [
        ("objectClass", [b"eduPerson", b"inetOrgPerson", b"person", b"voPerson"]),
        ("uid", person.encode()),
        (get_ldif_part("displayName", attributes)),
        (get_ldif_part("givenName", attributes)),
        (get_ldif_part("sn", attributes)),
        (get_ldif_part("cn", attributes, "eduPersonUniqueId")),
        (get_ldif_part("mail", attributes)),
        (get_ldif_part("eduPersonScopedAffiliation", attributes)),
        (get_ldif_part("eduPersonUniqueId", attributes)),
        (get_ldif_part("voPersonExternalID", attributes)),
        (get_ldif_part("voPersonExternalAffiliation", attributes)),
    ]

    if "sshPublicKey" in attributes:
        ldif[0][1].append(b"ldapPublicKey")
        ldif.append((get_ldif_part("sshPublicKey", attributes)))

    return ldif


def add_flat_people(connection, data):
    """docstring"""
    basedn = data["ldap"]["basedn"]
    dn = f"ou=People,dc={FLAT},{basedn}"
    ldif = [("objectClass", [b"top", b"organizationalUnit"]), ("ou", [b"People"])]
    connection.add_s(dn, ldif)

    for person, attributes in data["people"].items():
        dn = f"uid={person},ou=People,dc={FLAT},{basedn}"
        ldif = get_people_ldif(person, attributes)
        connection.add_s(dn, ldif)


def add_flat_groups(connection, data):
    """docstring"""
    basedn = data["ldap"]["basedn"]
    dn = f"ou=Groups,dc={FLAT},{basedn}"
    ldif = [("objectClass", [b"top", b"organizationalUnit"]), ("ou", [b"Groups"])]
    connection.add_s(dn, ldif)

    for org, org_data in data["groups"].items():
        for co, co_data in org_data["cos"].items():
            for group, group_data in co_data["groups"].items():
                rdn = f"cn={org}.{co}.{group}"
                dn = f"{rdn},ou=Groups,dc={FLAT},{basedn}"
                ldif = [
                    ("objectClass", [b"extensibleObject", b"groupOfMembers"]),
                    (get_ldif_part("description", group_data)),
                    (get_ldif_part("displayName", group_data)),
                    (get_ldif_part("uniqueIdentifier", group_data)),
                ]
                members = []
                for member in group_data["members"]:
                    members.append(f"uid={member},ou=People,dc={FLAT},{basedn}".encode())
                ldif.append(("member", members))

                connection.add_s(dn, ldif)


def add_ordered_services(connection, data):
    basedn = data["ldap"]["basedn"]

    for org, org_data in data["groups"].items():
        for co, co_data in org_data["cos"].items():
            dn_co = f"o={org}.{co},dc={ORDERED},{basedn}"
            ldif = [
                ("objectClass", [b"top", b"extensibleObject", b"organization"]),
                ("o", [f"{org}.{co}".encode()]),
                (get_ldif_part("displayName", co_data)),
                (get_ldif_part("description", co_data)),
            ]
            connection.add_s(dn_co, ldif)

            dn_groups = f"ou=Groups,{dn_co}"
            ldif = [("objectClass", [b"top", b"organizationalUnit"])]
            connection.add_s(dn_groups, ldif)

            people = set(co_data["non-group-members"])
            for group, group_data in co_data["groups"].items():
                dn_group = f"cn={group},{dn_groups}"
                ldif = [
                    ("objectClass", [b"extensibleObject", b"groupOfMembers"]),
                    ("cn", [group.encode()]),
                    (get_ldif_part("displayName", group_data)),
                ]

                members = []
                for member in group_data["members"]:
                    people.add(member)
                    members.append(f"uid={member},ou=People,{dn_co}".encode())
                ldif.append(("member", members))
                connection.add_s(dn_group, ldif)

            dn_group = f"cn=@all,{dn_groups}"
            ldif = [
                ("objectClass", [b"extensibleObject", b"groupOfMembers"]),
                ("cn", [b"@all"]),
                ("displayName", [b"All group"]),
            ]

            members = []
            for member in people:
                members.append(f"uid={member},ou=People,{dn_co}".encode())

            ldif.append(("member", members))
            connection.add_s(dn_group, ldif)

            add_ordered_people(connection, dn_co, people, data)


def add_ordered_people(connection, dn_co, people, data):
    """add people entry"""
    dn_people = f"ou=People,{dn_co}"
    ldif = [("objectClass", [b"top", b"organizationalUnit"]), ("ou", b"People")]
    connection.add_s(dn_people, ldif)

    for person in people:
        dn_uid = f"uid={person},{dn_people}"
        attributes = data["people"][person]
        ldif = get_people_ldif(person, attributes)
        connection.add_s(dn_uid, ldif)


def flat(connection, data):
    """docstring"""
    basedn = data["ldap"]["basedn"]
    add_ou_rdn(connection, basedn, FLAT)

    add_flat_people(connection, data)
    add_flat_groups(connection, data)


def ordered(connection, data):
    """docstring"""
    basedn = data["ldap"]["basedn"]
    add_ou_rdn(connection, basedn, ORDERED)

    add_ordered_services(connection, data)


def main():
    """Main function."""
    data = {}

    with open("test/data.json") as fd:
        data = json.load(fd)

    complete_data(data)

    with open("test/data.json", "w") as fd:
        json.dump(data, fd)

    ldap_conn = init_ldap(data["ldap"], {}, "ddd")

    flat(ldap_conn, data)
    ordered(ldap_conn, data)

    if len(sys.argv) == 2:
        with open(sys.argv[1], "w") as fd:
            json.dump(data, fp=fd, indent=2)


if __name__ == "__main__":
    main()
