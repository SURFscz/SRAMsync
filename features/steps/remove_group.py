"""Behave test"""

# pylint: skip-file

from test.ldap_support import remove_group

from behave import *
from click.testing import CliRunner

from SRAMsync.config import Config
from SRAMsync.sync_with_sram import cli, init_ldap

CONFIG_FILENAME = "test/config/config.yaml"


@given("Synchronized CO with a group")  # pyright: ignore
def step_remove_group(context):  # pyright: ignore
    """Behave given step"""
    config = Config(CONFIG_FILENAME)
    context.cfg = config
    context.ldap_conn = init_ldap(config["sram"], config.secrets, config["service"])

    assert True


@when("the group is removed")  # pyright: ignore
def step_remove_group(context):
    """Behave when step"""

    context._runner.stop_capture()

    remove_group(context.ldap_conn, "Hogwarts", "Gryffindor", "wizardry_owl")

    runner = CliRunner()
    result = runner.invoke(cli, [CONFIG_FILENAME])
    assert result.exit_code == 0


@then("all users are removed")  # pyright: ignore
def step_remove_group(context):
    """Behave then step"""
    assert True
