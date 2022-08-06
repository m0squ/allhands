import time, uuid


class Message:
    def __init__(self, sender, content, _type):
        self.sender = sender
        self.timestamp = time.time()
        self.content = content
        self.id = uuid.uuid4()
        self.type = _type

    @property
    def serialize(self):
        return {
            "sender": self.sender,
            "timestamp": self.timestamp,
            "content": self.content,
            "id": self.id,
            "type": self.type
        }
