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

from datetime import datetime, timedelta
import docker
from prometheus_client import start_http_server, Gauge
import os
import platform
from typing import Dict, Any, List, Set, Union, Optional
import ipaddress
from time import sleep
import traceback

APP_NAME = "Docker engine networks prometheus exporter"

PROMETHEUS_EXPORT_PORT = int(os.getenv('PROMETHEUS_EXPORT_PORT', '9000'))
DOCKER_HOSTNAME = os.getenv('DOCKER_HOSTNAME', platform.node())
SCRAPE_INTERVAL = int(os.getenv('SCRAPE_INTERVAL', '10'))
MAX_RETRIES_IN_ROW = int(os.getenv('MAX_RETRIES_IN_ROW', '10'))

DOCKER_NETWORK_CONTAINER_USED_IPS = Gauge(
    'docker_network_container_used_ips',
    'Total used IPs in network on Host by containers',
    [
        'docker_hostname',
        'network_id',
        'network_name',
        'network_driver'
    ]
)

DOCKER_NETWORK_SERVICE_USED_IPS = Gauge(
    'docker_network_service_used_ips',
    'Total used IPs by services (as known to the Host)',
    [
        'docker_hostname',
        'network_id',
        'network_name',
        'network_driver'
    ]
)

DOCKER_NETWORK_USABLE_IPS = Gauge(
    'docker_network_usable_ips',
    'Total available useable IPs in network',
    [
        'docker_hostname',
        'network_id',
        'network_name',
        'network_driver'
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
            services_successful = False

            network_id_to_name: Dict[str, str] = {}
            usable_ips_by_id: Dict[str, int] = {}
            seen_ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
            network_drivers_by_id: Dict[str, str] = {}

            def add_seen(ip_addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> None:
                if ip_addr in seen_ips:
                    print_timed(f"WARN: seen {ip_addr} twice")
                seen_ips.add(ip_addr)

            networks = client.networks.list()
            for network in networks:

                configs: List[Dict[str, Any]] = network.attrs['IPAM']['Config']

                # why is this a list?
                config = next(filter(lambda x: 'Subnet' in x, configs), None)      

                # config is none for e.g. Host or none driver
                if config is None:
                    continue

                network_drivers_by_id[network.attrs['Id']] = network.attrs['Driver']
                network_id_to_name[network.attrs['Id']] = network.attrs['Name']

                subnet = config['Subnet']

                ip_network = ipaddress.ip_interface(subnet).network

                # first is gateway
                first_usable_ip = ip_network[1]
                # last is broadcast
                last_usable_ip = ip_network[-2]

                usable_ips = int.from_bytes(last_usable_ip.packed, 'big') - int.from_bytes(first_usable_ip.packed, 'big')

                DOCKER_NETWORK_USABLE_IPS.labels(**{
                    'docker_hostname': DOCKER_HOSTNAME,
                    'network_id': network.attrs['Id'],
                    'network_name': network.attrs['Name'],
                    'network_driver': network.attrs['Driver']
                }).set(
                    usable_ips
                )

                usable_ips_by_id[network.attrs['Id']] = usable_ips

            # seed empty
            used_ips_per_network_container: Dict[str, int] = { network_id: 0 for network_id in network_id_to_name.keys()}
            def increment_used_ips_containers(key: str) -> None:
                used_ips_per_network_container[key] = used_ips_per_network_container.get(key, 0) + 1

            for container in client.containers.list(all=True, ignore_removed=True):
                container_network_details: Dict[str, Any]
                for container_network_details in container.attrs['NetworkSettings']['Networks'].values():
                    container_network_id: str = container_network_details['NetworkID']
                    container_network_ip_address = container_network_details.get('IPAddress', '')
                    if container_network_ip_address != '':
                        add_seen(ipaddress.ip_interface(container_network_ip_address).ip)
                        increment_used_ips_containers(container_network_id)

            used_ips_per_network_service: Dict[str, int] = { network_id: 0 for network_id in network_id_to_name.keys()}
            def increment_used_ips_services(key: str) -> None:
                used_ips_per_network_service[key] = used_ips_per_network_service.get(key, 0) + 1

            try:
                services = client.services.list()
                services_successful = True
            except docker.errors.APIError:
                services = []
                pass

            for service in services:
                if 'Endpoint' not in service.attrs:
                    continue

                service_endpoint = service.attrs['Endpoint']
                if 'VirtualIPs' not in service_endpoint:
                    continue

                virtual_ips = service_endpoint['VirtualIPs']
                for virtual_ip in virtual_ips:
                    virtual_ip_network_id = virtual_ip['NetworkID']
                    if 'Addr' in virtual_ip:
                        virtual_ip_addr = virtual_ip['Addr']
                        add_seen(ipaddress.ip_interface(virtual_ip_addr).ip)
                        increment_used_ips_services(virtual_ip_network_id)

            for network_id, network_name in network_id_to_name.items():
                network_driver = network_drivers_by_id[network_id]

                DOCKER_NETWORK_CONTAINER_USED_IPS.labels(**{
                    'docker_hostname': DOCKER_HOSTNAME,
                    'network_id': network_id,
                    'network_name': network_name,
                    'network_driver': network_driver
                }).set(
                    used_ips_per_network_container[network_id]
                )

                if services_successful:

                    DOCKER_NETWORK_SERVICE_USED_IPS.labels(**{
                        'docker_hostname': DOCKER_HOSTNAME,
                        'network_id': network_id,
                        'network_name': network_name,
                        'network_driver': network_driver
                    }).set(
                        used_ips_per_network_service[network_id]
                    )


            sleep(SCRAPE_INTERVAL)
    finally:
        client.close()


if __name__ == '__main__':
    print_timed(f'Start prometheus client on port {PROMETHEUS_EXPORT_PORT}')
    start_http_server(PROMETHEUS_EXPORT_PORT, addr='0.0.0.0')
    
    failure_count = 0
    last_failure: Optional[datetime]
    while True:
        try:
            print_timed('Watch networks')
            watch_networks()
        except docker.errors.APIError:
            now = datetime.now()

            traceback.print_exc()

            last_failure = last_failure
            if last_failure < (now - timedelta.seconds(SCRAPE_INTERVAL * 10)):
                print_timed("detected docker APIError, but last error was a bit back, resetting failure count.")
                # last failure was a while back, reset
                failure_count = 0

            failure_count += 1
            if failure_count > MAX_RETRIES_IN_ROW:
                print_timed(f"failed {failure_count} in a row. exiting...")
                exit(1)

            last_failure = now
            print_timed(f"waiting {SCRAPE_INTERVAL} until next cycle")
            sleep(SCRAPE_INTERVAL)
