from EventHandler import EventHandler

class DelenaEventHandler(EventHandler):
    def userDeleted(self, user):
        return super().userDeleted(user)
