from neutronclient.v2_0 import client


class CustomNeutronClient(client.Client):

    address_groups_path = "/address-groups"
    address_group_path = "/address-groups/%s"
    add_address_group_addresses_path = "/address-groups/%s/add_addresses"
    remove_address_group_addresses_path = "/address-groups/%s/remove_addresses"

    def list_address_groups(self, retrieve_all=True, **_params):
        """Fetches a list of all address groups for a project."""
        return self.list('address_groups', self.address_groups_path, retrieve_all, **_params)

    def create_address_group(self, body=None):
        """Creates a new address group."""
        return self.post(self.address_groups_path, body=body)

    def delete_address_group(self, address_group):
        """Deletes the specified address group."""
        return self.delete(self.address_group_path % (address_group))

    def add_address_group_addresses(self, addr_grp, body=None):
        """Adds addresses to a address group."""
        return self.put(self.add_address_group_addresses_path % addr_grp, body=body)

    def delete_address_group_addresses(self, addr_grp, body=None):
        """Removes addresses from a address group."""
        return self.put(self.remove_address_group_addresses_path % addr_grp, body=body)
