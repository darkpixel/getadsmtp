#!/usr/bin/env python
import sys, ldap, argparse

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="Retrieve e-mail addresses from an LDAP server in postfix format")
parser.add_argument('-c', '--connect', required=True, action='store', help='The host to connect to (AD/Exchange Server)')
parser.add_argument('-i', '--insecure', action='store', help='Use insecure port 389 and no SSL')
parser.add_argument('-r', '--port', action='store', help='Port to use for connecting, defaults to 636')
parser.add_argument('-u', '--user', action='store', required=True, help='Username to use (either cn=blah,dc=cust,dc=local or blah@cust.local format)')
parser.add_argument('-p', '--password', action='store', required=True, help='Password')
parser.add_argument('-o', '--ou', action='store', required=True, help='Org Unit to export from')
parser.add_argument('-e', '--exchange-all', action='store_true', default=False, required=False, help='All exchange types (users, groups, contacts, public, and rooms)')
parser.add_argument('-eu', '--exchange-users', action='store_true', default=False, required=False, help='Exchange users only (with mailboxes)')
parser.add_argument('-eg', '--exchange-groups', action='store_true', default=False, required=False, help='Exchange groups only')
parser.add_argument('-ec', '--exchange-contacts', action='store_true', default=False, required=False, help='Exchange contacts only')
parser.add_argument('-ep', '--exchange-public', action='store_true', default=False, required=False, help='Exchange public folders only')
parser.add_argument('-er', '--exchange-rooms', action='store_true', default=False, required=False, help='Exchange rooms only')
parser.add_argument('-d', '--disabled', action='store_true', default=False, required=False, help='Return only disabled accounts (as opposed to returning only enabled accounts)')
parser.add_argument('-ne', '--non-exchange', action='store_true', default=False, required=False, help='AD users that do not have mailboxes')
parser.add_argument('-t', '--transport', action='store', required=False, help='Transport string')

#TODO: Need option to export to file instead of stdout/redirection

arg = parser.parse_args()

if arg.insecure:
    server = 'ldap://%s:%s' %(arg.connect, arg.port or '389')
else:
    server = 'ldaps://%s:%s' %(arg.connect, arg.port or '636')
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

ad = ldap.initialize(server)
ad.set_option(ldap.OPT_REFERRALS, 0)
ad.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
ad.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
ad.set_option( ldap.OPT_X_TLS_DEMAND, True )
ad.set_option( ldap.OPT_DEBUG_LEVEL, 255 )
ad.simple_bind_s(arg.user, arg.password)


def print_user_list(filter):
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


DisabledFilter = "(userAccountControl:1.2.840.113556.1.4.803:=2)"
EnabledFilter = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"

if arg.exchange_users or arg.exchange_all:
    if arg.disabled:
        filter = "(&(objectClass=user)(objectCategory=person)(mailNickname=*)(msExchHomeServerName=*)%s)" %(DisabledFilter)
    else:
        filter = "(&(objectClass=user)(objectCategory=person)(mailNickname=*)(msExchHomeServerName=*)%s)" %(EnabledFilter)
    print filter
    print_user_list(filter)

if arg.exchange_groups or arg.exchange_all:
    filter = "(|(&(objectCategory=group)(groupType:1.2.840.113556.1.4.804:=8)(!(groupType:1.2.840.113556.1.4.804:=2147483648))(mailNickname=*))(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483656)(mailNickname=*))(&(objectCategory=group)(!(groupType:1.2.840.113556.1.4.804:=8))(mailNickname=*))(&(objectCategory=msExchDynamicDistributionList)(mailNickname=*)))"
    print_user_list(filter)

if arg.exchange_contacts or arg.exchange_all:
    filter = "(&(objectClass=contact)(mailNickname=*))"
    print_user_list(filter)

if arg.exchange_public or arg.exchange_all:
    filter = "(&(objectCategory=publicFolder)(mailNickname=*))"
    print_user_list(filter)

if arg.exchange_rooms or arg.exchange_all:
    filter = "(&(mailNickname=*)(|(msExchRecipientDisplayType=7)(msExchRecipientDisplayType=-2147481850)))"
    print_user_list(filter)

if arg.non_exchange:
    if arg.disabled:
        filter = "(&(objectClass=user)(!(msExchHomeServerName=*))%s)" %(DisabledFilter)
    else:
        filter = "(&(objectClass=user)(!(msExchHomeServerName=*))%s)" %(EnabledFilter)
    print_user_list(filter)

