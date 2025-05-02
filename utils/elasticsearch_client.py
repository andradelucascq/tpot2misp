#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Elasticsearch client utilities optimized for T-Pot's Nginx proxy.
"""

import logging
import requests
from typing import Dict, Any, Optional, List
import urllib3

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class ElasticClient:
    """Simple elasticsearch client for T-Pot's Nginx proxy"""
    
    def __init__(
        self,
        url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 30
    ):
        """
        Initialize the Elasticsearch client
        
        Args:
            url: Elasticsearch URL (include trailing slash for Nginx)
            username: Basic auth username
            password: Basic auth password
            verify_ssl: Whether to verify SSL certificates
            timeout: Connection timeout in seconds
        """
        self.url = url
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.auth = None
        
        # Set up auth if credentials are provided
        if self.username and self.password:
            self.auth = (self.username, self.password)
        
        # T-Pot's Nginx proxy requires specific headers
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        logger.debug(f"Initialized ElasticClient for {url}")
    
    def search(self, index: str, query: Dict[str, Any], size: int = 100, _source: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute search query against Elasticsearch
        
        Args:
            index: Index name or pattern to search
            query: Elasticsearch query as a dict
            size: Maximum number of results to return
            _source: List of fields to return in _source
            
        Returns:
            Dict containing search results
        """
        try:
            # Construct request JSON
            request_body = {
                "query": query,
                "size": size
            }
            
            # Add source filtering if specified
            if _source:
                request_body["_source"] = _source
            
            # Build the complete URL
            search_url = f"{self.url.rstrip('/')}/{index.lstrip('/')}/_search"
            
            # Make the request with proper headers
            response = requests.post(
                search_url,
                auth=self.auth,
                verify=self.verify_ssl,
                headers=self.headers,
                json=request_body,
                timeout=self.timeout
            )
            
            # Raise for HTTP errors
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            
            # Log search info
            total_hits = result.get("hits", {}).get("total", {})
            if isinstance(total_hits, dict):
                total_count = total_hits.get("value", 0)
            else:
                total_count = total_hits or 0
                
            logger.debug(f"Search on {index} returned {total_count} hits")
            
            return result
            
        except requests.RequestException as e:
            logger.error(f"Error searching Elasticsearch at {self.url}: {str(e)}")
            raise
    
    def indices_get_alias(self, index: str = "*") -> Dict[str, Any]:
        """
        Get index aliases
        
        Args:
            index: Index pattern
            
        Returns:
            Dict containing index alias information
        """
        try:
            # Build the complete URL
            alias_url = f"{self.url.rstrip('/')}/{index.lstrip('/')}/_alias"
            
            # Make the request with proper headers
            response = requests.get(
                alias_url,
                auth=self.auth,
                verify=self.verify_ssl,
                headers=self.headers,
                timeout=self.timeout
            )
            
            # Raise for HTTP errors
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            return result
            
        except requests.RequestException as e:
            logger.error(f"Error getting index aliases from Elasticsearch at {self.url}: {str(e)}")
            raise
    
    def info(self) -> Dict[str, Any]:
        """
        Get basic info about the Elasticsearch cluster
        
        Returns:
            Dict containing cluster info
        """
        try:
            # Make the request with proper headers
            response = requests.get(
                self.url,
                auth=self.auth,
                verify=self.verify_ssl,
                headers=self.headers,
                timeout=self.timeout
            )
            
            # Raise for HTTP errors
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            return result
            
        except requests.RequestException as e:
            logger.error(f"Error getting info from Elasticsearch at {self.url}: {str(e)}")
            raise

def create_elasticsearch_client(
    url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verify_ssl: bool = False,
    timeout: int = 30
) -> ElasticClient:
    """
    Create properly configured Elasticsearch client for T-Pot's Nginx proxy.
    
    Args:
        url: Elasticsearch URL (include trailing slash for Nginx)
        username: Basic auth username
        password: Basic auth password
        verify_ssl: Whether to verify SSL certificates
        timeout: Connection timeout in seconds
        
    Returns:
        Configured Elasticsearch client
    """
    try:
        client = ElasticClient(
            url=url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout
        )
        
        # Test connection (will raise exception if it fails)
        client.info()
        logger.debug(f"Successfully connected to Elasticsearch at {url}")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to Elasticsearch at {url}: {str(e)}")
        raise
