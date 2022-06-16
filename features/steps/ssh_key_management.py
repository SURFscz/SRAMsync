"""Behave test"""

from test.ldap_support import get_ssh_keys, add_ssh_key, remove_ssh_key

from click.testing import CliRunner
from SRAMsync.config import Config
from SRAMsync.sync_with_sram import cli, init_ldap


CONFIG_FILENAME = "test/config/config.yaml"

ORG = "Rivendell"
CO = "Fellowship"
UID = "samwise"
SSH_KEY = b"ssh-ed25519 This-is-a-test-ssh-key sam@rivendell"


@given("Samwise's key is not present yet")
def step_add_ssh_key(context):
    """Behave given step"""

    config = Config(CONFIG_FILENAME)
    ldap_conn = init_ldap(config["sram"], config.secrets, config["service"])
    context.cfg = config
    context.ldap_conn = ldap_conn

    try:
        keys = get_ssh_keys(ldap_conn, ORG, CO, UID)
        assert SSH_KEY not in keys
    except KeyError:
        pass


@when("Samwise adds a new SSH key")
def step_add_ssh_key(context):
    """Behave when step"""

    add_ssh_key(context.ldap_conn, ORG, CO, UID, SSH_KEY)


@then("The add-ssh-key event is emitted")
def step_add_ssh_key(context):
    """Behave then step"""

    try:
        keys = get_ssh_keys(context.ldap_conn, ORG, CO, UID)
        assert SSH_KEY in keys
    except KeyError:
        assert False

    runner = CliRunner()
    result = runner.invoke(cli, ["--log-level=info", CONFIG_FILENAME])
    assert result.exit_code == 0

    assert "add_public_ssh_key" in result.stdout


@given("Samwise's key exists")
def step_remove_ssh_key(context):
    """Behave given step"""

    config = Config(CONFIG_FILENAME)
    ldap_conn = init_ldap(config["sram"], config.secrets, config["service"])
    context.cfg = config
    context.ldap_conn = ldap_conn

    keys = get_ssh_keys(ldap_conn, ORG, CO, UID)
    assert SSH_KEY in keys


@when("Samwise removes an existing key")
def step_remove_ssh_key(context):
    """Behave when step"""
    remove_ssh_key(context.ldap_conn, ORG, CO, UID, SSH_KEY)
    keys = get_ssh_keys(context.ldap_conn, ORG, CO, UID)
    assert SSH_KEY not in keys


@then("The remove-ssh-key event is emitted")
def step_remove_ssh_key(context):
    """Behave given step"""
    runner = CliRunner()
    result = runner.invoke(cli, ["--log-level=info", CONFIG_FILENAME])
    assert result.exit_code == 0
    assert "delete_public_ssh_key" in result.stdout
