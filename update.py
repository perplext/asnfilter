#!/usr/bin/env python
#
# Updates the IPs and hosts blacklists
#
import uuid

from urllib.parse import urlparse

import redis
import requests
import yaml


def get_update(url):
    try:
        response = requests.head(url)

        if 'Last-Modified' in response.headers:
            current = response.headers['Last-Modified']
        else:
            current = uuid.uuid4().hex

        key = 'ASNfilter/sources/' + url + ':last-modified'

        old = r.get(key)
        if old is None:
            old = b''

        if current == old.decode('utf-8'):
            return None

        r.set(key, current)

        return requests.get(url).text
    except:
        raise


def populate_from_url(url, blacklist):
    print('Updating ' + blacklist + ' from: ' + url)

    bkey = 'ASNfilter/sources/' + blacklist + '_list'
    key = 'ASNfilter/sources/' + url
    update = get_update(url)

    if update is None:
        r.sadd(bkey, key)

        print('Nothing new.')

        return

    entries = []
    for line in update.splitlines():
        if line.startswith('#') or line.startswith('/') or line.isspace() or \
                len(line) == 0:
            continue

        fields = line.split()

        if blacklist == 'ips':
            entries.append(fields[0].strip())
            continue

        if len(fields) > 1:
            if fields[1].strip().startswith('#'):
                entry = fields[0].strip()
            else:
                entry = fields[1].strip()
        else:
            entry = fields[0].strip()

        if '/' not in entry:
            entries.append(entry)
        else:
            entries.append(urlparse(entry).netloc)

    key = 'ASNfilter/sources/' + url

    r.delete(key)
    r.sadd(key, *entries)
    r.sadd(bkey, key)

    print('Added ' + str(r.scard(key)) + ' entries')


def main():
    global r

    with open('config.yml') as f:
        config = yaml.load(f.read())

    pool = redis.ConnectionPool.from_url(config['dnsproxy']['redis'])
    r = redis.StrictRedis(connection_pool=pool)

    r.delete('ASNfilter/sources/hosts_list')
    for url in config['sources']['hosts']:
        populate_from_url(url, 'hosts')

    r.sunionstore('ASNfilter/host_blacklist',
                  r.smembers('ASNfilter/sources/hosts_list'))

    print('Total hosts: ' + str(r.scard('ASNfilter/host_blacklist')))

    r.delete('ASNfilter/sources/ips_list')
    for url in config['sources']['ips']:
        populate_from_url(url, 'ips')

    r.sunionstore('ASNfilter/ip_blacklist',
                  r.smembers('ASNfilter/sources/ips_list'))

    print('Total IPs: ' + str(r.scard('ASNfilter/ip_blacklist')))


if __name__ == '__main__':
    main()
