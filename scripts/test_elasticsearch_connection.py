#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Diagnostic script to test Elasticsearch connection with proper headers.
"""

import os
import sys
import json
import logging
from pathlib import Path
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from utils.elasticsearch_client import create_elasticsearch_client

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Test Elasticsearch connection with settings from .env"""
    # Load environment variables
    dotenv_path = Path(__file__).parent.parent / '.env'
    if dotenv_path.exists():
        load_dotenv(dotenv_path)
        logger.info(f"Loaded environment from {dotenv_path}")
    else:
        logger.warning(f"No .env file found at {dotenv_path}")
    
    # Get Elasticsearch connection parameters
    es_url = os.getenv("ELASTICSEARCH_URL")
    es_user = os.getenv("ELASTICSEARCH_USER")
    es_password = os.getenv("ELASTICSEARCH_PASSWORD")
    verify_ssl = os.getenv("ELASTICSEARCH_VERIFY_SSL", "false").lower() == "true"
    
    if not es_url:
        logger.error("ELASTICSEARCH_URL not set. Please configure in .env file")
        sys.exit(1)
    
    logger.info(f"Testing connection to Elasticsearch at {es_url}")
    logger.info(f"Authentication enabled: {bool(es_user and es_password)}")
    logger.info(f"SSL verification: {verify_ssl}")
    
    try:
        # Create client with the utility function
        client = create_elasticsearch_client(
            url=es_url,
            username=es_user,
            password=es_password,
            verify_ssl=verify_ssl
        )
        
        # Test the connection
        info = client.info()
        logger.info("✅ Connection successful!")
        logger.info(f"Cluster name: {info.get('cluster_name')}")
        logger.info(f"Elasticsearch version: {info.get('version', {}).get('number')}")
        
        # List indices to further validate connection
        indices = client.indices.get_alias(index="*")
        logger.info(f"Found {len(indices)} indices")
        
        # List a few honeypot indices if they exist
        for honeypot in ["cowrie", "dionaea"]:
            try:
                pattern = f"{honeypot}-*"
                honeypot_indices = client.indices.get_alias(index=pattern)
                logger.info(f"Found {len(honeypot_indices)} {honeypot} indices")
            except Exception as e:
                logger.warning(f"No {honeypot} indices found: {str(e)}")
        
        logger.info("✅ Connection test completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"❌ Connection failed: {str(e)}")
        
        # Provide guidance based on error type
        if "unauthorized" in str(e).lower() or "401" in str(e):
            logger.error("Authentication failed. Check username/password in .env file")
            logger.error("Make sure to use the same credentials as for T-Pot web interface")
        
        elif "media_type_header_exception" in str(e).lower():
            logger.error("Header incompatibility detected!")
            logger.error("This should be fixed by our custom client, but if you're seeing this:")
            logger.error("1. Make sure you're using the latest version of elasticsearch-py")
            logger.error("2. Verify RequestsHttpConnection is being used")
            logger.error("3. Check Nginx configuration for any custom header restrictions")
        
        elif "certificate" in str(e).lower() or "ssl" in str(e).lower():
            logger.error("SSL/Certificate error. Try setting ELASTICSEARCH_VERIFY_SSL=false")
        
        elif "connection" in str(e).lower() or "connect" in str(e).lower():
            logger.error("Connection error. Verify:")
            logger.error("1. The T-Pot machine is reachable at the specified URL")
            logger.error("2. The URL includes the correct port (usually 64297)")
            logger.error("3. The URL path ends with /es
            logger.error("4. No firewall is blocking the connection")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())
