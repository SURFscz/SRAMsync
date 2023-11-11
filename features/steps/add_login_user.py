"""Behave test"""

import re
from test.ldap_support import add_user, is_member_of, uid_exists

# from behave import *
from click.testing import CliRunner

from SRAMsync.config import Config
from SRAMsync.sync_with_sram import cli, init_ldap

CONFIG_FILENAME = "test/config/config.yaml"


@given("Eowyn is unknown to sync-with-sram")
def step_add_login_user(context):
    """Behave given step"""

    config = Config(CONFIG_FILENAME)
    ldap_conn = init_ldap(config["sram"], config.secrets, config["service"])
    context.cfg = config
    context.ldap_conn = ldap_conn

    assert uid_exists(ldap_conn, "Rivendell", "Fellowship", "eowyn") is False
    assert is_member_of(ldap_conn, "Rivendell", "Fellowship", "shirecloud_login", "eowyn") is False

    runner = CliRunner()
    result = runner.invoke(cli, [CONFIG_FILENAME])
    assert result.exit_code == 0


@when("Eowyn is added to a login group")
def step_add_login_user(context):
    """Behave when step"""

    add_user(context.ldap_conn, "Rivendell", "Fellowship", "shirecloud_login", "eowyn")


@then("add_new_user is printed to stdout.")
def step_add_login_user(context):
    """Behave then step"""

    runner = CliRunner()
    result = runner.invoke(cli, ["--log-level=info", CONFIG_FILENAME])
    assert result.exit_code == 0
    assert "add_new_user" in result.stdout
