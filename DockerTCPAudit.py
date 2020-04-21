#!/usr/bin/python3
#coding: utf-8
import docker
from concurrent.futures import ThreadPoolExecutor

netcat = []
stdout = '{:<15s} : {:<30s}'

def getNetworks(client):
    networks = client.networks.list()
    n = []
    for network in networks:
        network.reload()
        d = {'name': network.name, 'containers': network.containers, 'labels': network.attrs['Labels']}
        n.append(d)
    return n

def getContainers(client):
    return sorted(client.containers.list(), key=lambda x: x.name)

def parsePorts(ports):
    p = []
    for port in ports:
        port, protocol = port.split('/')
        d = {'port': port, 'protocol': protocol}
        p.append(d)
    return sorted(p, key=lambda x: int(x['port']))

def Netcat(container_id, ip, port):
    c = client.containers.get(container_id)
    rc, output = c.exec_run('nc -w 1 -vz {} {}'.format(ip, port))
    return rc, output

def WithNetcat(container):
    c = client.containers.get(container.id)
    rc, output = c.exec_run('which nc')
    if not rc == 0:
        netcat = False
    else:
        netcat = True
    d = {'name': container.name, 'netcat': netcat}
    return d

def Display(result):
    for i in result:
        print(stdout.format('Network', i['network']))
        print(stdout.format('Source', i['source'].name))
        print(stdout.format('Destination', i['destination'].name))
        print(stdout.format('Destination IP', i['destination_ip']))
        print(stdout.format('Port', i['port']))
        if not i['netcat']:
            print(stdout.format('Result', "Netcat is not available !"))
        else:
            print(stdout.format('Result', str(i['result'])))
        print()

def Product(containers, networks):
    product = []
    for container in containers:
        if not container.ports:
            continue
        container_ports = parsePorts(container.ports.keys())
        container_networks = sorted(container.attrs['NetworkSettings']['Networks'])
        for container_network in sorted(container.attrs['NetworkSettings']['Networks']):
            container_ip = container.attrs['NetworkSettings']['Networks'][container_network]['IPAddress']
            for connect_container in list(filter(lambda networks: networks['name'] == container_network, networks))[0]['containers']:
                if connect_container == container:
                    continue
                for port in container_ports:
                    if port['protocol'] == 'tcp':
                        d = {
                            'network': container_network,
                            'source': connect_container,
                            'destination': container,
                            'destination_ip': container_ip,
                            'port': port['port'],
                            'netcat': netcat
                        }
                        product.append(d)
    return product

def TCPAudit(product):
    if not [ x['netcat'] for x in netcat if x['name'] == product['source'].name][0]:
        product['netcat'] = False
        return product
    rc, output = Netcat(product['source'].id, product['destination_ip'], product['port'])
    if not rc == 0:
        product['result'] = False
    else:
        product['result'] = True
    return product

if __name__ == '__main__':
    client = docker.DockerClient(base_url='unix://var/run/docker.sock')
    n = getNetworks(client)
    c = getContainers(client)
    with ThreadPoolExecutor(max_workers=10) as executor:
        for i in executor.map(WithNetcat, c):
            netcat.append(i)
    product = Product(c, n)
    res = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for i in executor.map(TCPAudit, product):
            if i:
                res.append(i)
    Display(res)
