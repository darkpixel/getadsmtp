#!/usr/bin/env python
# Copyright (c) 2010-2014 Aaron C. de Bruyn <aaron@heyaaron.com>
# Licensed under the "Simplified BSD License"

import sys, ldap, argparse

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="Retrieve e-mail addresses from an LDAP server in postfix format")
parser.add_argument('-c', '--connect', required=True, action='store', help='The host to connect to (AD/Exchange Server)')
parser.add_argument('-r', '--port', action='store', help='Port to use for connecting, defaults to 636')
parser.add_argument('-u', '--user', action='store', required=True, help='Username to use (either cn=blah,dc=cust,dc=local or blah@cust.local format)')
parser.add_argument('-p', '--password', action='store', required=True, help='Password')
parser.add_argument('-o', '--ou', action='store', required=True, help='Org Unit to export from')
parser.add_argument('-e', '--exchange', action='store_true', default=False, required=False, help='Exchange mailboxes only')
parser.add_argument('-t', '--transport', action='store', required=False, help='Transport string')

arg = parser.parse_args()


server = 'ldaps://%s:%s' %(arg.connect, arg.port or '636')

if arg.exchange:
     filter = "(&(&(& (mailnickname=*) (| (&(objectCategory=person)(objectClass=user)(|(homeMDB=*)(msExchHomeServerName=*)))(objectCategory=group) ))))"
else:
     filter = "(mailNickname=*)"

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

ad = ldap.initialize(server)
ad.set_option(ldap.OPT_REFERRALS, 0)
ad.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
ad.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
ad.set_option( ldap.OPT_X_TLS_DEMAND, True )
ad.set_option( ldap.OPT_DEBUG_LEVEL, 255 )
ad.simple_bind_s(arg.user, arg.password)

res = ad.search(arg.ou, ldap.SCOPE_SUBTREE, filter, None)

#TODO: Filter out disabled accounts
#TODO: Provide option to 'REJECT' disabled accounts with a message

while True:
    datatype,data = ad.result(res, 0)
    if not datatype:
        break
    else:
        if datatype == ldap.RES_SEARCH_RESULT:
            break
        if datatype == ldap.RES_SEARCH_ENTRY:
            if hasattr(data[0][1], 'has_key') and data[0][1].has_key('proxyAddresses'):
                addresses = data[0][1]['proxyAddresses']
                for addr in addresses:
                    if 'smtp' in addr.lower():
                        if arg.transport:
                             print "%s\t\t%s" %(addr.lower().split('smtp:')[1], arg.transport)
                        else:
                             print "%s\t\tOK" %(addr.lower().split('smtp:')[1])

