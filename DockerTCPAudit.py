#!/usr/bin/python3
#coding: utf-8
import docker
from concurrent.futures import ThreadPoolExecutor

stdout = '{:<20s} : {:<40s}'

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

def Display(result):
    for i in result:
        print()
        print(stdout.format('Network', i['network']))
        print(stdout.format('Source', i['source'].name))
        print(stdout.format('Destination', i['destination'].name))
        print(stdout.format('Source IP', i['source'].attrs['NetworkSettings']['Networks'][i['network']]['IPAddress']))
        print(stdout.format('Destination IP', i['destination'].attrs['NetworkSettings']['Networks'][i['network']]['IPAddress']))
        print(stdout.format('Port', i['port']))
        print(stdout.format('Result', i['result']))

def Product(containers, networks):
    product = []
    for container in containers:
        if not container.ports:
            continue
        container_ports = parsePorts(container.ports.keys())
        container_networks = sorted(container.attrs['NetworkSettings']['Networks'])
        for container_network in sorted(container.attrs['NetworkSettings']['Networks']):
            for connect_container in list(filter(lambda networks: networks['name'] == container_network, networks))[0]['containers']:
                if connect_container == container:
                    continue
                for port in container_ports:
                    if port['protocol'] == 'tcp':
                        d = {
                            'network': container_network,
                            'source': connect_container,
                            'destination': container,
                            'port': port['port'],
                        }
                        product.append(d)
    return product

def TCPAudit(product):
    rc, output = Netcat(product)
    if rc == 1:
        product['result'] = "Close"
    elif rc == 0:
        product['result'] = "Open"
    else:
        product['result'] = "Netcat is not available !"
    return product

def Netcat(product):
    source = product['source'].id
    destination = product['destination'].attrs['NetworkSettings']['Networks'][product['network']]['IPAddress']
    port = product['port']
    c = client.containers.get(source)
    rc, output = c.exec_run('nc -w 1 -vz {} {}'.format(destination, port))
    return rc, output

if __name__ == '__main__':
    client = docker.DockerClient(base_url='unix://var/run/docker.sock')
    n = getNetworks(client)
    print(stdout.format('Total Networks', str(len(n))))
    c = getContainers(client)
    print(stdout.format('Total Containers', str(len(c))))
    product = Product(c, n)
    print(stdout.format('Total TCP Checks', str(len(product))))
    res = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        for i in executor.map(TCPAudit, product):
            if i:
                res.append(i)
    Display(res)
