"""Behave test"""

# pylint: skip-file

import json
import time
from test.ldap_support import add_user, remove_user_from_group

# from behave import *
from click.testing import CliRunner
from deepdiff import DeepDiff

from SRAMsync.config import Config
from SRAMsync.sync_with_sram import cli, init_ldap

CONFIG_FILENAME = "test/config/config.yaml"


@given("frodo is in the group")
def remove_frodo_from_shirecloud_login(context):
    """Behave given step"""
    config = Config(CONFIG_FILENAME)
    context.cfg = config
    context.ldap_conn = init_ldap(config["sram"], config.secrets, config["service"])

    runner = CliRunner()
    result = runner.invoke(cli, [CONFIG_FILENAME])
    assert result.exit_code == 0


@when("frodo is removed from LDAP")
def remove_frodo_from_shirecloud_login(context):
    """Behave when step"""
    assert (
        remove_user_from_group(context.ldap_conn, "Rivendell", "Fellowship", "shirecloud_login", "frodo")
        is True
    )


@then("Removal message is displayed on the command line")
def remove_frodo_from_shirecloud_login(context):
    """Behave when step"""
    config = Config(CONFIG_FILENAME)
    context.cfg = config
    context.ldap_conn = init_ldap(config["sram"], config.secrets, config["service"])

    runner = CliRunner()
    result = runner.invoke(cli, ["--log-level=info", CONFIG_FILENAME])
    assert result.exit_code == 0
    assert (
        "User 'middle_earth-Fellowship-frodo' has been removed but not deleted due to grace time."
        in result.stdout
    )


@given("Grace period for frodo has not ended")
def removing_frodo_before_the_grace_period_has_ened(context):
    with open("test/status/shirecloud.json") as fd:
        status = json.load(fd)

    context.status_file = status


@when("the sync-with-sram is run")
def removing_frodo_before_the_grace_period_has_ened(context):
    pass


@then("a warning message is displayed")
def removing_frodo_before_the_grace_period_has_ened(context):
    config = Config(CONFIG_FILENAME)
    context.cfg = config
    context.ldap_conn = init_ldap(config["sram"], config.secrets, config["service"])

    runner = CliRunner()
    result = runner.invoke(cli, ["--log-level=info", CONFIG_FILENAME])
    print(result.stdout)
    assert result.exit_code == 0
    assert "middle_earth-Fellowship-frodo from shirecloud_login has" in result.stdout
    assert "left of its grace time" in result.stdout


@then("the status file is unchanged")
def removing_frodo_before_the_grace_period_has_ened(context):
    with open("test/status/shirecloud.json") as fd:
        status = json.load(fd)

    assert DeepDiff(context.status_file, status, ignore_order=True) == {}


@given("frodo has been removed")
def frodo_is_permanently_removed(context):
    pass


@when("the grace period has passed")
def frodo_is_permanently_removed(context):
    """Behave when step"""
    time.sleep(6)


@then("frodo is permmanently removed from the group")
def frodo_is_permanently_removed(context):
    config = Config(CONFIG_FILENAME)
    context.cfg = config
    context.ldap_conn = init_ldap(config["sram"], config.secrets, config["service"])

    runner = CliRunner()
    result = runner.invoke(cli, ["--log-level=info", CONFIG_FILENAME])
    assert result.exit_code == 0
    assert "remove_graced_user_from_group" in result.stdout
