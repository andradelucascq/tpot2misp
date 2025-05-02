"""
Utilities for validating and checking IP addresses.
"""

import ipaddress
from typing import Union, Optional

def is_valid_ip(ip_str: Union[str, int, float, None]) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip_str: String to check
        
    Returns:
        True if valid IP address, False otherwise
    """
    if ip_str is None:
        return False
    
    if not isinstance(ip_str, str):
        return False
        
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_private_ip(ip_str: Union[str, None]) -> bool:
    """
    Check if an IP address is private.
    
    Args:
        ip_str: IP address to check
        
    Returns:
        True if IP is private, False otherwise
    """
    if not is_valid_ip(ip_str):
        return False
        
    try:
        ip = ipaddress.ip_address(ip_str)
        # Loopback IPs são considerados privados pelo ipaddress,
        # mas queremos tratá-los separadamente
        if ip.is_loopback:
            return False
        # Reserved IPs não devem ser considerados privados para os testes
        if ip.is_reserved:
            return False
        return ip.is_private
    except ValueError:
        return False

def is_reserved_ip(ip_str: Union[str, None]) -> bool:
    """
    Check if an IP address is reserved.
    
    Args:
        ip_str: IP address to check
        
    Returns:
        True if IP is reserved, False otherwise
    """
    if not is_valid_ip(ip_str):
        return False
        
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_reserved
    except ValueError:
        return False

def is_loopback_ip(ip_str: Union[str, None]) -> bool:
    """
    Check if an IP address is a loopback address.
    
    Args:
        ip_str: IP address to check
        
    Returns:
        True if IP is a loopback address, False otherwise
    """
    if not is_valid_ip(ip_str):
        return False
        
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback
    except ValueError:
        return False

def is_global_ip(ip_str: Union[str, None]) -> bool:
    """
    Check if an IP address is global (public).
    
    Args:
        ip_str: IP address to check
        
    Returns:
        True if IP is global, False otherwise
    """
    if not is_valid_ip(ip_str):
        return False
        
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False

def is_multicast_ip(ip_str: Union[str, None]) -> bool:
    """
    Check if an IP address is a multicast address.
    
    Args:
        ip_str: IP address to check
        
    Returns:
        True if IP is a multicast address, False otherwise
    """
    if not is_valid_ip(ip_str):
        return False
        
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_multicast
    except ValueError:
        return False

def get_ip_version(ip_str: Union[str, None]) -> Optional[int]:
    """
    Get the IP version of an IP address.
    
    Args:
        ip_str: IP address to check
        
    Returns:
        4 for IPv4, 6 for IPv6, None if invalid IP
    """
    if not is_valid_ip(ip_str):
        return None
        
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.version
    except ValueError:
        return None