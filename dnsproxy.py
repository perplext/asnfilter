import configparser
import encodings.idna
import grp
import os
import pwd
import socket

import geoip2.database
import redis

from twisted.internet import reactor
from twisted.names import client, dns, server
from twisted.names.dns import A, AAAA


idna = encodings.idna

r = None
reader = None


# https://stackoverflow.com/a/2699996
def drop_privileges(uid_name='nobody', gid_name='nobody'):
    if os.getuid() != 0:
        return

    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    os.setgroups([])

    os.setgid(running_gid)
    os.setuid(running_uid)


def get_ASN(ip_address):
    global reader

    try:
        asn = reader.asn(ip_address)
    except:
        asn = None

    return asn


def responseFilter(ip_address):
    global r

    try:
        asn = get_ASN(ip_address)

        r.set('ASNfilter/ASN/' + str(asn.autonomous_system_number),
              asn.autonomous_system_organization)

        if r.sismember('ASNfilter/blacklist',
                       str(asn.autonomous_system_number)):
            return True
    except:
        raise

    return False


class ASNFilterDNSServerFactory(server.DNSServerFactory):
    def __init__(self, authorities=None, caches=None, clients=None, verbose=0):
        self._sendReply = server.DNSServerFactory.sendReply

        server.DNSServerFactory.__init__(self, authorities, caches, clients,
                                         verbose)

    def sendReply(self, protocol, message, address):
        filtered = False
        for answer in message.answers:
            if answer.type == A:
                ip_address = answer.payload.dottedQuad()

                if responseFilter(ip_address):
                    filtered = True
                    break
            elif answer.type == AAAA:
                ip_address = socket.inet_ntop(socket.AF_INET6,
                                              answer.payload.address)

                if responseFilter(ip_address):
                    filtered = True
                    break
            else:
                continue

        if filtered is True:
            message.rCode = 3  # NXDOMAIN
            message.answers = []

        return self._sendReply(self, protocol, message, address)


def main():
    global r, reader

    config = configparser.ConfigParser()
    config.read('asnfilter.conf')

    pool = redis.ConnectionPool.from_url(config.get('dnsproxy', 'redisurl'))
    r = redis.StrictRedis(connection_pool=pool)

    reader = geoip2.database.Reader(config.get('dnsproxy', 'asndb'))

    servers = []
    for entry in config.get('dnsproxy', 'servers').split(','):
        servers.append((entry.replace(' ', ''), 53))

    factory = ASNFilterDNSServerFactory(
        clients=[client.Resolver(servers=servers)]
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(int(config.get('dnsproxy', 'port')), protocol)
    reactor.listenTCP(int(config.get('dnsproxy', 'port')), factory)

    drop_privileges(config.get('dnsproxy', 'user'),
                    config.get('dnsproxy', 'group'))

    reactor.run()


if __name__ == '__main__':
    main()
