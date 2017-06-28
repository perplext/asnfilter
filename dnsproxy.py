import encodings.idna
import grp
import os
import pwd
import socket

import geoip2.database
import redis
import yaml

from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server
from twisted.names.dns import A, AAAA


idna = encodings.idna

r = None
reader = None


# Credit: https://stackoverflow.com/a/2699996
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
        if r.sismember('ASNfilter/ip_whitelist', ip_address):
            return False

        if r.sismember('ASNfilter/ip_blacklist', ip_address):
            return True

        asn = get_ASN(ip_address)

        r.set('ASNfilter/ASN/' + str(asn.autonomous_system_number),
              asn.autonomous_system_organization)

        if r.sismember('ASNfilter/asn_whitelist',
                       str(asn.autonomous_system_number)):
            return False

        if r.sismember('ASNfilter/asn_blacklist',
                       str(asn.autonomous_system_number)):
            return True
    except:
        raise

    return False


def queriesFilter(queries):
    global r

    for query in queries:
        if r.sismember('ASNfilter/host_whitelist', query.name.name.lower()):
            return False

        if r.sismember('ASNfilter/host_blacklist', query.name.name.lower()):
            return True

    return False


class ASNFilterResolver(client.Resolver):
    def __init__(self, resolv=None, servers=None, timeout=(1, 3, 11, 45),
                 reactor=None):
        self._queryUDP = client.Resolver.queryUDP
        self._queryTCP = client.Resolver.queryTCP

        client.Resolver.__init__(self, resolv, servers, timeout, reactor)

    def queryUDP(self, queries, timeout=None):
        if queriesFilter(queries):
            return defer.fail(error.DomainError())
        else:
            return self._queryUDP(self, queries, timeout)

    def queryTCP(self, queries, timeout=10):
        if queriesFilter(queries):
            return defer.fail(error.DomainError())
        else:
            return self._queryTCP(self, queries, timeout)


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

    with open('config.yml') as f:
        config = yaml.load(f.read())

    pool = redis.ConnectionPool.from_url(config['dnsproxy']['redis'])
    r = redis.StrictRedis(connection_pool=pool)

    reader = geoip2.database.Reader(config['dnsproxy']['asndb'])

    servers = []
    for entry in config['dnsproxy']['servers']:
        servers.append((entry, 53))

    factory = ASNFilterDNSServerFactory(
        clients=[ASNFilterResolver(servers=servers)]
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(config['dnsproxy']['port'], protocol)
    reactor.listenTCP(config['dnsproxy']['port'], factory)

    drop_privileges(config['dnsproxy']['user'],
                    config['dnsproxy']['group'])

    reactor.run()


if __name__ == '__main__':
    main()
