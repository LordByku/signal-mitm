from src.mitm_interface import MitmUser, MitmVisitenKarte, VisitenKarteType
from signal_protocol.address import ProtocolAddress

class MitmUserOrchestrator:
    """
    Orchestrates the management of MitmUser instances.
    """

    def __init__(self):
        self.users = {}

    def get_or_create_user(self, protocol_address: ProtocolAddress, aci_uuid: str, pni_uuid: str) -> MitmUser:
        """
        Retrieve or create a MitmUser based on its protocol address and UUIDs.
        """
        key = (protocol_address.name(), protocol_address.device_id())
        if key not in self.users:
            user = MitmUser(protocol_address, aci_uuid, pni_uuid)
            self.users[key] = user
        return self.users[key]

    def update_user(self, protocol_address: ProtocolAddress, update_data):
        """
        Update user data (e.g., phone number or keys).
        """
        key = (protocol_address.name(), protocol_address.device_id())
        if key in self.users:
            user = self.users[key]
            if 'phone_number' in update_data:
                user._phone_number = update_data['phone_number']
            if 'unidentified_access_key' in update_data:
                user._unidentified_access_key = update_data['unidentified_access_key']
            # Add other update logic as needed.

    def list_users(self):
        """
        Return a list of all managed users.
        """
        return list(self.users.values())

    def __repr__(self):
        return f"MitmUserOrchestrator(users={len(self.users)})"
