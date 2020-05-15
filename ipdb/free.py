# -*- coding: utf-8 -*-
"""
    :copyright: ©2018 by IPIP.net
"""

from .database import *


class FreeInfo:
    country_name = ""
    region_name = ""
    city_name = ""
    anycast = ""

    def __init__(self, **kwargs):
        self._map = kwargs
        for key in self._map:
            self.__dict__[key] = self._map[key]

class FreeDump:

    db = None

    def __init__(self, name):
        self.db = Dumper(name)

    def reload(self, name):
        try:
            db = Dumper(name)
            self.db = db
            return True
        except:
            return False

    def dump_all(self, name):
        return self.db.dump_all(name)


class Free:

    db = None

    def __init__(self, name):
        self.db = Reader(name)

    def reload(self, name):
        try:
            db = Reader(name)
            self.db = db
            return True
        except:
            return False

    def find(self, addr, language):
        return self.db.find(addr, language)

    def find_map(self, addr, language):
        return self.db.find_map(addr, language)

    def find_info(self, addr, language):
        m = self.db.find_map(addr, language)
        if m is None:
            return None
        return FreeInfo(**m)

    def is_ipv4(self):
        return self.db.is_support_ipv4()

    def is_ipv6(self):
        return self.db.is_support_ipv6()

    def languages(self):
        return self.db.support_languages()

    def fields(self):
        return self.db.support_fields()

    def build_time(self):
        return self.db.build_utc_time()