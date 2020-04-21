#!/usr/bin/python3
#coding: utf-8
import docker

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

def WithNetcat(container_id):
    c = client.containers.get(container_id)
    rc, output = c.exec_run('which nc')
    if not rc == 0:
        return False
    return True

def TCPAudit(containers, networks):
    for container in containers:
        if not container.ports:
            continue
        container_ports = parsePorts(container.ports.keys())
        container_networks = sorted(container.attrs['NetworkSettings']['Networks'])
        print('=== {} INFORMATION ==='.format(container.name.upper()))
        print(stdout.format('Container', container.name))
        print(stdout.format('Ports', ', '.join(container.ports.keys())))
        print(stdout.format('Networks', ', '.join(container_networks)))
        print()
        print('=== {} TCP AUDIT ==='.format(container.name.upper()))
        for container_network in sorted(container.attrs['NetworkSettings']['Networks']):
            container_ip = container.attrs['NetworkSettings']['Networks'][container_network]['IPAddress']
            for connect_container in list(filter(lambda networks: networks['name'] == container_network, networks))[0]['containers']:
                if connect_container == container:
                    continue
                if not WithNetcat(connect_container.id):
                    print(stdout.format('Network', container_network))
                    print(stdout.format('Source', connect_container.name))
                    print(stdout.format('Destination', container.name))
                    print(stdout.format('Destination IP', container_ip))
                    print(stdout.format('Result', "Netcat is not available !"))
                    print()
                    continue
                for port in container_ports:
                    if port['protocol'] == 'tcp':
                        print(stdout.format('Network', container_network))
                        print(stdout.format('Source', connect_container.name))
                        print(stdout.format('Destination', container.name))
                        print(stdout.format('Destination IP', container_ip))
                        print(stdout.format('Port', port['port']))
                        print(stdout.format('Protocol', port['protocol']))
                        rc, output = Netcat(connect_container.id, container_ip, port['port'])
                        if rc == 0:
                            print(stdout.format('Result', 'True'))
                        else:
                            print(stdout.format('Result', 'False'))
                        print()
        print()

if __name__ == '__main__':
    client = docker.DockerClient(base_url='unix://var/run/docker.sock')
    n = getNetworks(client)
    c = getContainers(client)
    TCPAudit(c, n)
