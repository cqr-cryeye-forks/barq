import json


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, object):
            return obj.dict()
        return super().default(obj)
