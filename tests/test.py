#!/usr/bin/env python
from ldap_test import LdapServer
import ldap
import unittest


class FilterTests(unittest.TestCase):
    def __init__(self, methodName):
        self.server = LdapServer({
            'port': 3333,
            'bind_dn': 'cn=admin,dc=cust,dc=local',
            'password': 'trustno1',
            'base': {
                'objectclass': ['domain', 'top'],
                'dn': 'dc=cust,dc=local',
                'attributes': {'dc': 'cust'}
            },
            'ldifs': [
                'tests/user-container.ldif',
                'tests/enabled-exchange-user.ldif',
#               'tests/disabled-exchange-user.ldif',
                'tests/enabled-non-exchange-user.ldif',
                'tests/disabled-non-exchange-user.ldif',
            ]
        })

        self.server.start()
        super(FilterTests, self).__init__(methodName)

    def teardown_func(self):
        self.server.stop()

    def test_connectivity(self):
        dn = self.server.config['bind_dn']
        pw = self.server.config['password']
        con = ldap.initialize('ldap://localhost:%s' % (self.server.config['port'],))
        con.simple_bind_s(dn, pw)

        base_dn = self.server.config['base']['dn']
        filter = '(objectclass=*)'
        attrs = ['dc']

        print con.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, attrs)

