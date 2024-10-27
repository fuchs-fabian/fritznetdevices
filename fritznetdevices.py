#!/usr/bin/env python3

import configparser
import os
import sys
import platform
import time

import ipaddress
import socket
import subprocess
from fritzconnection.lib.fritzhosts import FritzHosts  # type: ignore

import requests  # type: ignore

import random
import pandas as pd  # type: ignore
import numpy as np  # type: ignore


CONFIG_FILE='config.ini'
DEVICE_CATEGORIES_FILE='device_categories.json'

CACHE_PATH='./cache'
EXPORTS_PATH='./exports'

MANUFACTURER_CACHE_NAME = 'manufacturer_cache'


def load_config():
    print(f"Loading config from '{CONFIG_FILE}'...")

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config


def save_df_to_cache(df, base_filename, description):
    print()
    print(f"Caching: {description}...")

    os.makedirs(CACHE_PATH, exist_ok=True)

    cache_file_base_path = os.path.join(CACHE_PATH, base_filename)

    df.to_json(f"{cache_file_base_path}.json", orient='records', indent=4)

    print(f"{description} | Cached '{CACHE_PATH}'.")
    print()


def load_cached_df(base_filename):
    cache_file=os.path.join(CACHE_PATH, f"{base_filename}.json")

    if os.path.exists(cache_file):
        print(f"Loading cache from '{cache_file}'...")
        cache_df = pd.read_json(cache_file)
        print("Cache loaded successfully.")
        return cache_df
    else:
        print(f"No cache file found at '{cache_file}'.")
        return pd.DataFrame()


def export_df_to_files(df, base_filename, description):
    print()
    print(f"Exporting: {description}...")

    export_dir = os.path.join(EXPORTS_PATH, base_filename)

    os.makedirs(EXPORTS_PATH, exist_ok=True)
    os.makedirs(export_dir, exist_ok=True)

    export_file_base_path = os.path.join(export_dir, base_filename)

    df.to_json(f"{export_file_base_path}.json", orient='records', indent=4)
    df.to_csv(f"{export_file_base_path}.csv", index=False)
    df.to_excel(f"{export_file_base_path}.xlsx", index=False)

    print(f"{description} | Exported to '{export_dir}' as JSON, CSV and Excel.")
    print()


def check_required_fields(df, required_fields):
    for field in required_fields:
        if field not in df.columns:
            print(f"Required field '{field}' not found in DataFrame.")
            return False
    return True


def verify_required_fields(df, required_fields, description):
    print()
    if not check_required_fields(df, required_fields):
        print(f"{description} | Required fields {required_fields} not found in DataFrame | Exiting...")
        sys.exit(1)
    else:
        print(f"{description}...")


def sort_dict_by_ip(dict):
    return sorted(
        dict,
        key=lambda x: (
            not x.get('ip'),
            ipaddress.ip_address(x['ip']) if x.get('ip') else ipaddress.ip_address('255.255.255.255')
        )
    )


def sort_ip_list(ip_list):
    return sorted(
        ip_list,
        key=lambda ip: ipaddress.ip_address(ip)
    )


def is_valid_mac_address(mac_address):
    if not mac_address:
        return False
    return len(mac_address) in [17, 12]


# ░░░░░░░░░░░░░░░░░░░░░▓▓▓░░░░░░░░░░░░░░░░░░░░░░
# ░░                                          ░░
# ░░                                          ░░
# ░░                Fritz!Box                 ░░
# ░░                                          ░░
# ░░                                          ░░
# ░░░░░░░░░░░░░░░░░░░░░▓▓▓░░░░░░░░░░░░░░░░░░░░░░

def get_fritzbox_connected_devices_df_from_api(config):
    print()
    print("Retrieving connected devices from Fritz!Box API...")

    config_key_fritzbox = 'fritzbox'

    address = config.get(config_key_fritzbox, 'address')
    username = config.get(config_key_fritzbox, 'username')
    password = config.get(config_key_fritzbox, 'password')
    
    hosts = FritzHosts(address=address, user=username, password=password)
    devices = hosts.get_hosts_info()

    fritzbox_devices_df = pd.DataFrame(sort_dict_by_ip(devices))

    # If you want to keep the lease time remaining, comment out the following line
    fritzbox_devices_df = fritzbox_devices_df.drop(columns=['lease_time_remaining'], errors='ignore')

    if 'status' in fritzbox_devices_df.columns:
        fritzbox_devices_df['status'] = fritzbox_devices_df['status'].apply(lambda x: 'active' if x else 'inactive')
    
    if 'interface_type' in fritzbox_devices_df.columns:
        fritzbox_devices_df = fritzbox_devices_df.rename(columns={'interface_type': 'connection_type'})
        fritzbox_devices_df['connection_type'] = fritzbox_devices_df['connection_type'].replace({
            'Ethernet': 'LAN',
            '802.11': 'WLAN'
        })

    print(f"Number of devices retrieved from Fritz!Box API: {len(fritzbox_devices_df)}")

    if 'status' in fritzbox_devices_df.columns:
        print("\nDevice status counts:")
        status_counts = fritzbox_devices_df['status'].value_counts()
        for status, count in status_counts.items():
            print(f"{status.capitalize()}: {count}")

    if 'connection_type' in fritzbox_devices_df.columns:
        print("\nConnection type counts:")
        connection_counts = fritzbox_devices_df['connection_type'].replace('', pd.NA).dropna().value_counts()
        for connection_type, count in connection_counts.items():
            print(f"{connection_type}: {count}")

    duplicate_ips = fritzbox_devices_df[fritzbox_devices_df['ip'].notna() & (fritzbox_devices_df['ip'] != '') & fritzbox_devices_df.duplicated(subset=['ip'], keep=False)]

    if not duplicate_ips.empty:
        print("\nWarning: Duplicate IP addresses detected!")
        duplicate_ip_counts = duplicate_ips['ip'].value_counts()
        for ip, count in duplicate_ip_counts.items():
            print(f"IP Address: {ip}, Count: {count}")
    else:
        print("\nNo duplicate IP addresses found.")

    print()

    return fritzbox_devices_df


# ░░░░░░░░░░░░░░░░░░░░░▓▓▓░░░░░░░░░░░░░░░░░░░░░░
# ░░                                          ░░
# ░░                                          ░░
# ░░                 FEATURES                 ░░
# ░░                                          ░░
# ░░                                          ░░
# ░░░░░░░░░░░░░░░░░░░░░▓▓▓░░░░░░░░░░░░░░░░░░░░░░


# ╔═════════════════════╦══════════════════════╗
# ║                                            ║
# ║          MANUFACTURER AND CATEGORY         ║
# ║                                            ║
# ╚═════════════════════╩══════════════════════╝


# ┌─────────────────────┬──────────────────────┐
# │                MANUFACTURER                │
# └─────────────────────┴──────────────────────┘

manufacturer_cache = {}
manufacturer_api_request_count = 0
manufacturer_cache_hit_count = 0


def get_device_manufacturer_from_api(mac_address):
    if not is_valid_mac_address(mac_address):
        print(f"Invalid MAC address: '{mac_address}'. Skipping.")
        return np.nan

    api_base_url = "https://api.macvendors.com"

    # Sleep for 1 second to avoid rate limiting. For more information, see https://macvendors.com/api
    wait_time_to_avoid_rate_limit = 1 # seconds

    global manufacturer_api_request_count, manufacturer_cache_hit_count

    # Reduce MAC address to the first three bytes (6 hexadecimal characters)
    mac_prefix = mac_address[:8]  # Example: "00:1A:2B"

    if mac_prefix in manufacturer_cache:
        manufacturer_cache_hit_count += 1

        if manufacturer_cache[mac_prefix] is None:
            return np.nan
        else:
            print(f"Cache | {mac_address}: {manufacturer_cache[mac_prefix]}")
            return manufacturer_cache[mac_prefix]

    try:
        time.sleep(wait_time_to_avoid_rate_limit)

        response = requests.get(f"{api_base_url}/{mac_prefix}")
        manufacturer_api_request_count += 1

        if response.status_code == 200:
            manufacturer = response.text
            manufacturer_cache[mac_prefix] = manufacturer
            print(f"API | {mac_address}: {manufacturer}")
            return manufacturer

        elif response.status_code == 429:
            wait_time = random.uniform(10, 20)
            print(f"Current MAC address: {mac_address}. Rate limit exceeded. Waiting {wait_time} seconds before retrying | API requests made: {manufacturer_api_request_count} | Cache hits: {manufacturer_cache_hit_count}")
            time.sleep(wait_time)
            return get_device_manufacturer_from_api(mac_address)

        elif response.status_code == 404:
            print(f"API | {mac_address} | Manufacturer not found!")
            manufacturer_cache[mac_prefix] = None
            return np.nan

    except Exception as e:
        print(f"Error when retrieving manufacturer information for {mac_address}: {e}")
        manufacturer_cache[mac_prefix] = None
        return np.nan


def add_col_for_manufacturer(devices_df):
    verify_required_fields(devices_df, ['mac'], 'Manufacturer retrieval from API')

    global manufacturer_cache
    cached_df = load_cached_df(MANUFACTURER_CACHE_NAME)

    if cached_df.empty or 'mac' not in cached_df.columns or 'manufacturer' not in cached_df.columns:
        print("Cache is empty or incorrectly formatted. Starting with an empty cache.")
        manufacturer_cache = {}
    else:
        manufacturer_cache = cached_df.set_index('mac')['manufacturer'].to_dict()

    devices_df['manufacturer'] = devices_df['mac'].apply(get_device_manufacturer_from_api)

    print()
    print(f"Total API requests made: {manufacturer_api_request_count}")
    print(f"Total cache hits: {manufacturer_cache_hit_count}")
    print()

    manufacturer_cache_df = pd.DataFrame.from_dict(manufacturer_cache, orient='index', columns=['manufacturer']).reset_index()
    manufacturer_cache_df.columns = ['mac', 'manufacturer']
    save_df_to_cache(manufacturer_cache_df, MANUFACTURER_CACHE_NAME, "Manufacturer cache")

    return devices_df


def save_manufacturer_count(devices_df):
    manufacturer_count_df = devices_df['manufacturer'].value_counts().reset_index()
    manufacturer_count_df.columns = ['manufacturer', 'count']

    export_df_to_files(
        df=manufacturer_count_df,
        base_filename='manufacturers',
        description='Manufacturer counts'
    )


# ┌─────────────────────┬──────────────────────┐
# │                 CATEGORY                   │
# └─────────────────────┴──────────────────────┘

def load_manufacturer_categories():
    data = pd.read_json(DEVICE_CATEGORIES_FILE)
    categories_df = data.explode('manufacturers').rename(columns={'manufacturers': 'manufacturer'})
    return categories_df


def add_col_for_category(devices_df):
    verify_required_fields(devices_df, ['manufacturer'], 'Category retrieval')

    categories_df=load_manufacturer_categories()

    devices_with_category_df = devices_df.merge(
        categories_df,
        on='manufacturer',
        how='left'
    )

    devices_df['category'] = devices_with_category_df['category']

    print()
    print("Category counts:")
    for category, count in devices_with_category_df['category'].value_counts(dropna=False).items():
        if pd.isna(category):
            print(f"Uncategorized: {count}")
        else:
            print(f"{category}: {count}")
    print()

    return devices_df


# ╔═════════════════════╦══════════════════════╗
# ║                                            ║
# ║               WEB INTERFACES               ║
# ║                                            ║
# ╚═════════════════════╩══════════════════════╝

def check_if_device_has_web_interface(ip, status):
    if not ip:
        return None

    if status == 'inactive':
        return None

    for port in [80, 443]:
        url = f"http://{ip}:{port}" if port == 80 else f"https://{ip}:{port}"
        try:
            response = requests.get(url, timeout=3)
            if response.status_code >= 200 and response.status_code < 400:
                print(f"{ip}: {url}")
                return True
        except requests.RequestException:
            continue
    print(f"{ip} | No web interface found!")
    return False


def add_col_for_web_interface(devices_df):
    verify_required_fields(devices_df, ['ip', 'status'], 'Web interface retrieval')

    devices_df['web_interface'] = devices_df.apply(
        lambda row: check_if_device_has_web_interface(row['ip'], row['status']),
        axis=1
    )

    web_interface_counts = devices_df['web_interface'].value_counts(dropna=False)

    print()
    print("Web interface counts:")
    for value, count in web_interface_counts.items():
        if value is True:
            print(f"Devices with a web interface: {count}")
        elif value is False:
            print(f"Devices without a web interface: {count}")
        else:
            print(f"Devices with unknown web interface status: {count}")
    print()

    return devices_df


# ╔═════════════════════╦══════════════════════╗
# ║                                            ║
# ║          HOSTNAME AND IP ADDRESSES         ║
# ║                                            ║
# ╚═════════════════════╩══════════════════════╝


# ┌─────────────────────┬──────────────────────┐
# │              PRIMARY HOSTNAME              │
# └─────────────────────┴──────────────────────┘

def get_primary_hostname_from_ip(ip):
    if not ip:
        return None

    try:
        primary_hostname = socket.gethostbyaddr(ip)[0]
        print(f"{ip}: {primary_hostname}")
        return primary_hostname
    except socket.herror:
        print(f"{ip} | No primary hostname found!")
        return None


def create_ip_to_primary_hostname_df(devices_df):
    verify_required_fields(devices_df, ['ip'], 'Primary hostname retrieval')

    valid_ips_df = devices_df[['ip']].dropna(subset=['ip'])
    valid_ips_df = valid_ips_df[valid_ips_df['ip'].str.strip() != '']

    ip_to_primary_hostname_df = valid_ips_df.copy().drop_duplicates()

    ip_to_primary_hostname_df['primary_hostname'] = ip_to_primary_hostname_df['ip'].apply(get_primary_hostname_from_ip)

    return ip_to_primary_hostname_df


# ┌─────────────────────┬──────────────────────┐
# │          IP ADDRESSES AND HOSTNAMES        │
# └─────────────────────┴──────────────────────┘

def get_ip_addresses_and_hostnames(primary_hostname):
    if not primary_hostname:
        return [], [], []

    ipv4_addresses = set()
    ipv6_addresses = set()
    all_hostnames = set()

    try:
        addr_info = socket.getaddrinfo(primary_hostname, None)

        for addr in addr_info:
            ip_address = addr[4][0]
            if addr[0] == socket.AF_INET:  # IPv4
                ipv4_addresses.add(ip_address)
            elif addr[0] == socket.AF_INET6:  # IPv6
                ipv6_addresses.add(ip_address)

            try:
                hostname_info = socket.gethostbyaddr(ip_address)
                all_hostnames.update(hostname_info[1])  # hostname_info[1] returns all aliases
                all_hostnames.add(hostname_info[0])  # hostname_info[0] is the official name
            except socket.herror:
                continue

        print(f"{primary_hostname}: IPv4 -> {list(ipv4_addresses)} | IPv6 -> {list(ipv6_addresses)} | Hostnames -> {list(all_hostnames)}")
        return list(ipv4_addresses), list(ipv6_addresses), list(all_hostnames)
    except socket.gaierror:
        print(f"{primary_hostname} | No IP addresses found!")
        return [], [], []

def create_ip_to_hostname_df(devices_df):
    ip_to_hostname_df = create_ip_to_primary_hostname_df(devices_df)

    verify_required_fields(ip_to_hostname_df, ['primary_hostname'], 'IP address and hostname retrieval')

    ip_to_hostname_df[['ipv4_addresses', 'ipv6_addresses', 'all_hostnames']] = ip_to_hostname_df['primary_hostname'].apply(
        lambda hostname: pd.Series(get_ip_addresses_and_hostnames(hostname))
    )

    ip_to_hostname_df.rename(columns={
        'ipv4_addresses': 'ipv4_addresses_by_primary_hostname',
        'ipv6_addresses': 'ipv6_addresses_by_primary_hostname',
        'all_hostnames': 'all_hostnames_by_ipv4_address'
    }, inplace=True)

    ip_to_hostname_df['ipv4_addresses_by_primary_hostname'] = ip_to_hostname_df.apply(
        lambda row: list(set(row['ipv4_addresses_by_primary_hostname'])), axis=1
    )

    ip_to_hostname_df.dropna(subset=['primary_hostname'], inplace=True)

    return ip_to_hostname_df


def add_cols_for_hostnames(devices_df, ip_to_hostname_df):
    ip_all_hostnames_df = ip_to_hostname_df[['ip', 'primary_hostname', 'all_hostnames_by_ipv4_address']]

    devices_df = devices_df.merge(
        ip_all_hostnames_df,
        on='ip',
        how='left'
    )

    return devices_df


def save_ip_to_hostname_df(ip_to_hostname_df):
    export_df_to_files(
        df=ip_to_hostname_df,
        base_filename='ips_and_hostnames',
        description='IP addresses and hostnames'
    )


# ╔═════════════════════╦══════════════════════╗
# ║                                            ║
# ║            UNUSED IP ADDRESSES             ║
# ║                                            ║
# ╚═════════════════════╩══════════════════════╝

def get_network_cidr(config):
    return config.get('network', 'cidr')


def generate_all_ips_in_network(network_cidr):
    network = ipaddress.ip_network(network_cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


def find_free_ips_in_devices_df(config, devices_df):
    verify_required_fields(devices_df, ['ip'], 'Free IP address retrieval')

    network_cidr = get_network_cidr(config)
    all_ips = set(generate_all_ips_in_network(network_cidr))

    used_ips = set(devices_df['ip'].dropna())

    free_ips = all_ips - used_ips

    free_ips_df = pd.DataFrame(sort_ip_list(list(free_ips)), columns=['ip'])

    print()
    print(f"Number of free IPs in devices list: {len(free_ips_df)}")
    print()

    return free_ips_df


def determine_unused_ip_addresses(config, devices_df):
    unused_ips_df = find_free_ips_in_devices_df(config, devices_df)

    unused_ips_df['status'] = 'free'
    unused_ips_df['primary_hostname'] = None

    for index, row in unused_ips_df.iterrows():
        ip = row['ip']
        primary_hostname = get_primary_hostname_from_ip(ip)

        if primary_hostname:
            unused_ips_df.at[index, 'status'] = 'blocked'
            unused_ips_df.at[index, 'primary_hostname'] = primary_hostname

    print()

    print("Un/used IP addresses counts:")
    for status, count in unused_ips_df['status'].value_counts(dropna=False).items():
        print(f"{status}: {count}")

    print("\nBlocked IP addresses:")
    blocked_ips_df = unused_ips_df[unused_ips_df['status'] == 'blocked']
    for index, row in blocked_ips_df.iterrows():
        print(f"{row['ip']}: {row['primary_hostname']}")

    def ip_to_int(ip):
        return sum(int(part) << (8 * (3 - idx)) for idx, part in enumerate(ip.split('.')))

    def int_to_ip(ip_int):
        return '.'.join(str((ip_int >> (8 * i)) & 0xFF) for i in range(3, -1, -1))

    free_ips = unused_ips_df[unused_ips_df['status'] == 'free']['ip'].tolist()
    if free_ips:
        free_ip_ranges = []
        current_range_start = ip_to_int(free_ips[0])
        range_start = current_range_start

        for i in range(1, len(free_ips)):
            ip_int = ip_to_int(free_ips[i])
            if ip_int != current_range_start + 1:
                free_ip_ranges.append((int_to_ip(range_start), int_to_ip(current_range_start)))
                range_start = ip_int
            current_range_start = ip_int

        free_ip_ranges.append((int_to_ip(range_start), int_to_ip(current_range_start)))

        print("\nFree IP addresses:")
        for start, end in free_ip_ranges:
            if start == end:
                print(f"{start}")
            else:
                print(f"{start} - {end}")

    print()

    return unused_ips_df


def save_unused_ip_addresses(unused_ips_df):
    export_df_to_files(
        df=unused_ips_df,
        base_filename='unused_ips',
        description='Unused IP addresses'
    )


# ╔═════════════════════╦══════════════════════╗
# ║                                            ║
# ║             PING ALL DEVICES               ║
# ║                                            ║
# ╚═════════════════════╩══════════════════════╝

def ping_ip(ip):
    if not ip:
        return np.nan

    param = "-n" if platform.system().lower() == "windows" else "-c"

    is_reachable = False
    
    try:
        output = subprocess.run(
            ["ping", param, "1", ip],  # Ping 1 time
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        is_reachable = output.returncode == 0
    except Exception:
        is_reachable = False

    if is_reachable:
        print(f"{ip}: reachable")
    else:
        print(f"{ip}: not reachable")

    return is_reachable


def add_col_for_is_reachable(devices_df):
    verify_required_fields(devices_df, ['ip'], 'Ping')

    devices_df['is_reachable_over_ping'] = devices_df['ip'].apply(ping_ip)

    reachable_count = devices_df['is_reachable_over_ping'].dropna().sum()

    print()
    print(f"Number of reachable devices: {reachable_count}")
    print()

    return devices_df


# ░░░░░░░░░░░░░░░░░░░░░▓▓▓░░░░░░░░░░░░░░░░░░░░░░
# ░░                                          ░░
# ░░                                          ░░
# ░░                  MAIN                    ░░
# ░░                                          ░░
# ░░                                          ░░
# ░░░░░░░░░░░░░░░░░░░░░▓▓▓░░░░░░░░░░░░░░░░░░░░░░

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file '{CONFIG_FILE}' not found. Exiting.")
        return

    if not os.path.exists(DEVICE_CATEGORIES_FILE):
        print(f"Device categories file '{DEVICE_CATEGORIES_FILE}' not found. Exiting.")
        return

    config = load_config()
    devices_df = get_fritzbox_connected_devices_df_from_api(config)

    config_key_features = 'features'

    if config.getboolean(config_key_features, 'manufacturer_and_category'):
        devices_df = add_col_for_manufacturer(devices_df)
        devices_df = add_col_for_category(devices_df)
        save_manufacturer_count(devices_df)

    if config.getboolean(config_key_features, 'web_interface'):
        devices_df = add_col_for_web_interface(devices_df)

    if config.getboolean(config_key_features, 'hostname_and_ip_addresses'):
        ip_to_hostname_df = create_ip_to_hostname_df(devices_df)
        devices_df = add_cols_for_hostnames(devices_df, ip_to_hostname_df)
        save_ip_to_hostname_df(ip_to_hostname_df)

    if config.getboolean(config_key_features, 'determine_unused_ip_addresses'):
        unused_ips_df = determine_unused_ip_addresses(config, devices_df)
        save_unused_ip_addresses(unused_ips_df)

    if config.getboolean(config_key_features, 'ping_all_devices'):
        devices_df = add_col_for_is_reachable(devices_df)

    export_df_to_files(
        df=devices_df,
        base_filename='devices',
        description='Device data'
    )


if __name__ == '__main__':
    start_time = time.time()
    main()
    end_time = time.time()

    elapsed_time = end_time - start_time

    if elapsed_time >= 60:
        minutes = int(elapsed_time // 60)
        seconds = elapsed_time % 60
        print(f"\nElapsed time: {minutes} minute(s) and {seconds:.2f} second(s)")
    else:
        print(f"\nElapsed time: {elapsed_time:.2f} seconds")
