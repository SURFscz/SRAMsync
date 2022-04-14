
import pytest

from SRAMsync.common import deduct_event_handler_class
from SRAMsync.event_handler import EventHandler
from SRAMsync.dummy_event_handler import DummyEventHandler

from external_event_handler.my_external_event_handler import MyExternalEventHandler


class MyEventHandler(EventHandler):
    pass


def test_deduct_event_handler_class():
    # make sure that the standard SRAMsync lookup still works
    assert deduct_event_handler_class('DummyEventHandler') == DummyEventHandler

    # test the new loaded with a local event handler
    assert deduct_event_handler_class('test_common.MyEventHandler') == MyEventHandler

    # test the new loaded with an event handler in a different package
    assert deduct_event_handler_class('external_event_handler.my_external_event_handler.MyExternalEventHandler') == MyExternalEventHandler

    with pytest.raises(ModuleNotFoundError):
        deduct_event_handler_class("my_package.my_module.NotExistingEventHandler")
