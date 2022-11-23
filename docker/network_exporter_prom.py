#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2022 NeuroForge GmbH & Co. KG <https://neuroforge.de>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
import docker
from prometheus_client import start_http_server, Gauge
import os
import platform
from typing import Dict, Any, List, Set, Union
import ipaddress
from time import sleep

APP_NAME = "Docker engine networks prometheus exporter"

PROMETHEUS_EXPORT_PORT = int(os.getenv('PROMETHEUS_EXPORT_PORT', '9000'))
DOCKER_HOSTNAME = os.getenv('DOCKER_HOSTNAME', platform.node())
SCRAPE_INTERAL = int(os.getenv('SCRAPE_INTERVAL', '10'))

DOCKER_NETWORK_USED_IPS = Gauge(
    'docker_network_used_ips',
    'Total used IPs in network on Host',
    [
        'docker_hostname',
        'network_id',
        'network_name'
    ]
)

DOCKER_NETWORK_USABLE_IPS = Gauge(
    'docker_network_usable_ips',
    'Total available useable IPs in network',
    [
        'docker_hostname',
        'network_id',
        'network_name'
    ]
)

DOCKER_NETWORK_FREE_IPS = Gauge(
    'docker_network_free_ips',
    'Total available useable free IPs in network',
    [
        'docker_hostname',
        'network_id',
        'network_name'
    ]
)


def print_timed(msg):
    to_print = '{} [{}]: {}'.format(
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'docker_events',
        msg)
    print(to_print)


def watch_networks():
    client = docker.DockerClient()
    try:
        while True:
            network_id_to_name: Dict[str, str] = {}
            usable_ips_by_id: Dict[str, int] = {}
            seen_ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()

            def add_seen(ip_addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> None:
                if ip_addr in seen_ips:
                    raise AssertionError()
                seen_ips.add(ip_addr)

            networks = client.networks.list()
            for network in networks:

                configs: List[Dict[str, Any]] = network.attrs['IPAM']['Config']

                # why is this a list?
                config = next(filter(lambda x: 'Subnet' in x, configs), None)      

                # config is none for e.g. Host or none driver
                if config is None:
                    continue

                network_id_to_name[network.attrs['Id']] = network.attrs['Name']

                subnet = config['Subnet']

                ip_network = ipaddress.ip_network(subnet)

                # first is gateway
                first_usable_ip = ip_network[1]
                # last is broadcast
                last_usable_ip = ip_network[-2]

                usable_ips = int.from_bytes(last_usable_ip.packed, 'big') - int.from_bytes(first_usable_ip.packed, 'big')

                DOCKER_NETWORK_USABLE_IPS.labels(**{
                    'docker_hostname': DOCKER_HOSTNAME,
                    'network_id': network.attrs['Id'],
                    'network_name': network.attrs['Name']
                }).set(
                    usable_ips
                )

                usable_ips_by_id[network.attrs['Id']] = usable_ips

            # seed empty
            used_ips_per_network: Dict[str, int] = { network_id: 0 for network_id in network_id_to_name.keys()}

            def increment_used_ips(key: str) -> None:
                used_ips_per_network[key] = used_ips_per_network.get(key, 0) + 1

            for container in client.containers.list(all=True):
                container_network_details: Dict[str, Any]
                for container_network_details in container.attrs['NetworkSettings']['Networks'].values():
                    container_network_id: str = container_network_details['NetworkID']
                    container_network_ip_address = container_network_details.get('IPAddress', '')
                    if container_network_ip_address != '':
                        add_seen(ipaddress.ip_address(container_network_ip_address))
                        increment_used_ips(container_network_id)

            for service in client.services.list():
                if 'Endpoint' not in service.attrs:
                    continue

                service_endpoint = service.attrs['Endpoint']
                if 'VirtualIPs' not in service_endpoint:
                    continue

                virtual_ips = service_endpoint['VirtualIPs']
                for virtual_ip in virtual_ips:
                    virtual_ip_network_id = virtual_ip['NetworkID']
                    virtual_ip_addr = virtual_ip['Addr']
                    add_seen(ipaddress.ip_interface(virtual_ip_addr).ip)
                    increment_used_ips(virtual_ip_network_id)

            for network_id, network_name in network_id_to_name.items():
                used_ips = used_ips_per_network[network_id]

                DOCKER_NETWORK_USED_IPS.labels(**{
                    'docker_hostname': DOCKER_HOSTNAME,
                    'network_id': network_id,
                    'network_name': network_name
                }).set(
                    used_ips
                )

                DOCKER_NETWORK_FREE_IPS.labels(**{
                    'docker_hostname': DOCKER_HOSTNAME,
                    'network_id': network_id,
                    'network_name': network_name
                }).set(
                    usable_ips_by_id[network_id] - used_ips
                )

            sleep(SCRAPE_INTERAL)
    finally:
        client.close()


if __name__ == '__main__':
    print_timed(f'Start prometheus client on port {PROMETHEUS_EXPORT_PORT}')
    start_http_server(PROMETHEUS_EXPORT_PORT, addr='0.0.0.0')
    try:
        print_timed('Watch docker events')
        watch_networks()
    except docker.errors.APIError:
        pass
