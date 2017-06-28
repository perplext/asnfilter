import uuid

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


def populate_from_hosts_url(url):
    print('Updating hosts from: ' + url)

    key = 'ASNfilter/sources/' + url
    update = get_update(url)

    if update is None:
        r.sadd('ASNfilter/sources/hosts_list', key)

        print('Nothing new.')

        return

    hosts = []
    for line in update.splitlines():
        if line.startswith('#') or line.startswith('/') or line.isspace() or \
                len(line) == 0:
            continue

        fields = line.split()
        if len(fields) > 1:
            if fields[1].strip().startswith('#'):
                entry = fields[0].strip()
            else:
                entry = fields[1].strip()
        else:
            entry = fields[0].strip()

        if '/' not in entry:
            hosts.append(entry)

    key = 'ASNfilter/sources/' + url

    r.delete(key)
    r.sadd(key, *hosts)
    r.sadd('ASNfilter/sources/hosts_list', key)

    print('Added ' + str(r.scard(key)) + ' hosts')


def populate_from_ips_url(url):
    print('updating ips from: ' + url)

    update = get_update(url)
    print(update)


def main():
    global r

    with open('config.yml') as f:
        config = yaml.load(f.read())

    pool = redis.ConnectionPool.from_url(config['dnsproxy']['redis'])
    r = redis.StrictRedis(connection_pool=pool)

    r.delete('ASNfilter/sources/hosts_list')
    for url in config['sources']['hosts']:
        populate_from_hosts_url(url)

    r.sunionstore('ASNfilter/host_blacklist',
                  r.smembers('ASNfilter/sources/hosts_list'))

    print('Total hosts: ' + str(r.scard('ASNfilter/host_blacklist')))

    # for url in config['sources']['ips']:
    #     populate_from_ips_url(url)


if __name__ == '__main__':
    main()
