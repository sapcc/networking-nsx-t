import yaml
from yaml.loader import SafeLoader


class e2eConfig():

    def __init__(self, path=None, validator_fn=None):
        self.path = path
        self.validator = validator_fn
        self.load_conf()

    def load_conf(self):
        with open(self.path) as f:
            self.raw_data = yaml.load(f, Loader=SafeLoader)

    def validate_conf(self):
        return self.validator()

    def show_conf(self):
        for key, value in self.raw_data.items():
            print(key, '->', value)

    def get_conf_by_key(self, key):
        return self.raw_data[key]

    def get_conf(self):
        return self.raw_data

    def image(self):
        return self.raw_data.get("IMAGE")

    def flavor(self):
        return self.raw_data.get("FLAVOR")

    def key(self):
        return self.raw_data.get("KEY")

    def _server(self, name="server_name"):
        server = self.raw_data.get(name)
        server["IMAGE"] = self.image()
        server["KEY"] = self.key()
        server["FLAVOR"] = self.flavor()
        return server

    def servers(self):
        return [self._server("RED"), self._server("BLUE")]

    def trunk(self):
        return self.raw_data.get("TRUNK")
