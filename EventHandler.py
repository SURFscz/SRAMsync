from abc import ABC, abstractmethod


class EventHandler(ABC):
    def __init__(self, generator):
        self.generator = generator

    @abstractmethod
    def userDeleted(self, user):
        self.generator.userDeleted(user)
