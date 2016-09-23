import re


def isdigit(n):
    split = n.split('.')
    return n.isdigit() or (len(split) == 2 and all(map(str.isdigit, split)))


def parse_interval(t):
    if isdigit(t):
        return float(t)
    unit = t[-1].lower()
    num = t[:-1]
    if not isdigit(num):
        raise ValueError('Invalid interval: %s' % t)
    num = float(num)
    for i, u in enumerate(('s', 'm', 'h')):
        if unit == u:
            return num
        num *= 60
    raise ValueError('Invalid interval: %s' % t)


server_name_reg = re.compile(r'server_name (.+);')


def parse_server_names(s):
    result = []
    names = server_name_reg.findall(s)
    [result.extend(i.split()) for i in names if i != '_']
    return result


DOMAIN_LABEL = 'interlock.domain'
HOSTNAME_LABEL = 'interlock.hostname'


def get_server_names(client):
    """
    :type client: docker.Client
    """
    names = []
    services = client.services()
    for s in services:
        labels = s['Spec']['Labels']
        if DOMAIN_LABEL in labels and HOSTNAME_LABEL in labels:
            names.append('.'.join((labels[DOMAIN_LABEL], labels[HOSTNAME_LABEL])))
    return names


def get_manager_ips(client):
    """
    :type client: docker.Client
    """
    managers = client.nodes(dict(role='manager'))
    return [m['ManagerStatus']['Addr'].split(':')[0]
            for m in managers if m['Status']['State'] == 'ready']


def diff_list(n1, n2):
    s1 = set(n1)
    s2 = set(n2)
    adds = s2 - s1
    dels = s1 - s2
    return adds, dels


if __name__ == '__main__':
    with open('eg.nginx.conf') as f:
        print parse_server_names(f.read())
