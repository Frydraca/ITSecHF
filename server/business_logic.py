class BLL:

    def __init__(self):
        self.session_store = dict()

    def resolve_message(self, msg):
        print(msg)