import json
from session import Session

class BLL:

    def __init__(self):
        self.session_store = dict()

    def basic_validate_message(self, msg_obj):
        return "client_id" in msg_obj.keys() and "data" in msg_obj.keys() and "type" in msg_obj["data"].keys()

    def validate_ini(self, msg_obj):
        return msg_obj["client_id"] not in self.session_store.keys() and "pub_key" in msg_obj["data"].keys() and "pub_curve_key" in msg_obj["data"].keys()

    def resolve_message(self, byte_msg):
        msg = byte_msg.decode('utf-8')
        msg_obj = json.loads(msg)
        if self.basic_validate_message(msg_obj):
            print()
            print("Incoming message:")
            print(json.dumps(msg_obj, indent=2))

            if msg_obj["data"]["type"] == "INI":
                if self.validate_ini(msg_obj):
                   newSession = Session()
                   newSession.clientId = msg_obj["client_id"]
                   newSession.clientPubKey = msg_obj["data"]["pub_key"]
                   newSession.clientCurvePubKey = msg_obj["data"]["pub_curve_key"]

                   self.session_store.update({msg_obj["client_id"] : newSession})
                   print()
                   print("Session store updated:")
                   print(json.dumps(self.session_store.keys(), indent=2))

        
        print("Bad Message")
