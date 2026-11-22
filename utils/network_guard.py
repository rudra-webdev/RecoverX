"""
Network Guard Module for RecoverX
Enforces strict offline isolation by blocking network socket connections and external requests.
"""
import socket
from utils.logging_config import logger

_network_blocked = False

def enable_offline_mode():
    """
    Enforces offline isolation by intercepting socket creation and connections.
    Prevents any direct or transitive network requests.
    """
    global _network_blocked
    if _network_blocked:
        return

    orig_connect = socket.socket.connect
    orig_create_connection = socket.create_connection
    orig_sendto = socket.socket.sendto
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname

    def blocked_connect(self, address):
        raise PermissionError(
            f"RecoverX Offline Security Guard: Network connection to {address} is strictly blocked."
        )

    def blocked_create_connection(address, *args, **kwargs):
        raise PermissionError(
            f"RecoverX Offline Security Guard: Outbound connection to {address} is strictly blocked."
        )

    def blocked_sendto(self, *args, **kwargs):
        raise PermissionError(
            "RecoverX Offline Security Guard: Outbound transmission (sendto) is strictly blocked."
        )

    def blocked_getaddrinfo(*args, **kwargs):
        target = args[0] if args else "unknown"
        raise PermissionError(
            f"RecoverX Offline Security Guard: DNS address lookup for '{target}' is strictly blocked."
        )

    def blocked_gethostbyname(hostname):
        raise PermissionError(
            f"RecoverX Offline Security Guard: DNS hostname lookup for '{hostname}' is strictly blocked."
        )

    socket.socket.connect = blocked_connect
    socket.create_connection = blocked_create_connection
    socket.socket.sendto = blocked_sendto
    socket.getaddrinfo = blocked_getaddrinfo
    socket.gethostbyname = blocked_gethostbyname

    _network_blocked = True
    logger.info("RecoverX Offline Mode active: Network socket access disabled.")

def is_offline_mode_active() -> bool:
    return _network_blocked

