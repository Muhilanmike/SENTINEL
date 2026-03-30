import pytest
import numpy as np


@pytest.fixture
def sample_tcp_packet():
    return {
        "timestamp": "2026-03-30T10:00:00",
        "length": 64,
        "protocol": "TCP",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "ttl": 64,
        "src_port": 45678,
        "dst_port": 80,
        "tcp_flags": "0x018",  # PSH+ACK
        "transport": "TCP",
    }


@pytest.fixture
def sample_udp_packet():
    return {
        "timestamp": "2026-03-30T10:00:00",
        "length": 128,
        "protocol": "UDP",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "ttl": 128,
        "src_port": 55000,
        "dst_port": 53,
        "transport": "UDP",
    }


@pytest.fixture
def sample_mdns_packet():
    return {
        "timestamp": "2026-03-30T10:00:00",
        "length": 80,
        "protocol": "UDP",
        "src_ip": "172.21.144.1",
        "dst_ip": "224.0.0.251",
        "ttl": 255,
        "src_port": 5353,
        "dst_port": 5353,
        "transport": "UDP",
    }


@pytest.fixture
def sample_upnp_packet():
    return {
        "timestamp": "2026-03-30T10:00:00",
        "length": 200,
        "protocol": "UDP",
        "src_ip": "192.168.1.50",
        "dst_ip": "239.255.255.250",
        "ttl": 4,
        "src_port": 55236,
        "dst_port": 1900,
        "transport": "UDP",
    }


@pytest.fixture
def sample_syn_flood_packet():
    return {
        "timestamp": "2026-03-30T10:00:00",
        "length": 54,
        "protocol": "TCP",
        "src_ip": "10.10.10.10",
        "dst_ip": "192.168.1.1",
        "ttl": 64,
        "src_port": 12345,
        "dst_port": 22,
        "tcp_flags": "0x002",  # SYN only
        "transport": "TCP",
    }


@pytest.fixture
def sample_multicast_packet():
    """Packet to a multicast address not explicitly in whitelist but in 224.0.0.0/4."""
    return {
        "timestamp": "2026-03-30T10:00:00",
        "length": 100,
        "protocol": "UDP",
        "src_ip": "192.168.1.5",
        "dst_ip": "224.0.0.100",
        "ttl": 1,
        "src_port": 40000,
        "dst_port": 9999,
        "transport": "UDP",
    }


@pytest.fixture
def sample_features():
    return np.array([
        64.0,   # packet_length
        64.0,   # ttl
        45678,  # src_port
        80.0,   # dst_port
        1.0,    # is_tcp
        0.0,    # is_udp
        0.0,    # is_icmp
        1.0,    # is_http
        0.0,    # is_https
        0.0,    # is_dns
        0.0,    # is_ssh
        0.0,    # is_ftp
        0.0,    # tcp_flag_syn
        1.0,    # tcp_flag_ack
        0.0,    # tcp_flag_fin
        0.0,    # tcp_flag_rst
        1.0,    # tcp_flag_psh
    ])
