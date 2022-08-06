import time, uuid


class File:
    def __init__(self, sender, filename):
        self.sender = sender
        self.timestamp = time.time()
        self.filename = filename
        #self.id = uuid.uuid4()

    @property
    def serialize(self):
        return {
            "sender": self.sender,
            "timestamp": self.timestamp,
            "filename": self.filename,
        }
