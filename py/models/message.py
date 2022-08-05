import time, uuid

"""class File:
    def __init__(self, name, content):
        self.name = name
        self.content = content"""


class Message:
    def __init__(self, sender, content, _type, file):
        self.sender = sender
        self.timestamp = time.time()
        self.content = content
        self.id = uuid.uuid4()
        self.type = _type
        #File(file["name"], file["content"])
        self.file = file

    @property
    def serialize(self):
        return {
            "sender": self.sender,
            "timestamp": self.timestamp,
            "content": self.content,
            "id": self.id,
            "type": self.type,
            "file": self.file,
        }
