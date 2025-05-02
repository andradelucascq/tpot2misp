#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Diagnostic script to test MISP connection and API functionality.
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Test MISP connection with settings from .env"""
    # Load environment variables
    dotenv_path = Path(__file__).parent.parent / '.env'
    if dotenv_path.exists():
        load_dotenv(dotenv_path)
        logger.info(f"Loaded environment from {dotenv_path}")
    else:
        logger.warning(f"No .env file found at {dotenv_path}")
    
    # Get MISP connection parameters
    misp_url = os.getenv("MISP_URL")
    misp_key = os.getenv("MISP_KEY")
    verify_ssl = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
    
    if not misp_url or not misp_key:
        logger.error("MISP_URL or MISP_KEY not set. Please configure in .env file")
        return 1
    
    logger.info(f"Testing connection to MISP at {misp_url}")
    logger.info(f"API key provided: {'Yes' if misp_key else 'No'}")
    logger.info(f"SSL verification: {verify_ssl}")
    
    try:
        # Import PyMISP here to avoid import errors if not testing MISP
        from pymisp import PyMISP, MISPEvent
        
        # Create PyMISP client
        misp = PyMISP(misp_url, misp_key, ssl=verify_ssl)
        
        # Test connection by getting server info
        logger.info("Testing MISP API by retrieving server information...")
        
        # Modificar esta parte do script
        try:
            # Versão mais recente da PyMISP
            version = misp.get_version()
            logger.info(f"✅ Connection successful!")
            logger.info(f"MISP version: {version}")
        except AttributeError:
            try:
                # Tentativa com método alternativo para versões anteriores
                server_info = misp.server_info()
                logger.info(f"✅ Connection successful!")
                logger.info(f"MISP version: {server_info.get('version')}")
            except Exception as e:
                logger.error(f"❌ Could not retrieve MISP version using either method: {e}")
        
        # Test retrieving recent events
        logger.info("Testing retrieval of recent events...")
        events = misp.search(controller='events', limit=5, published=True)
        
        # Count events returned
        if isinstance(events, list):
            logger.info(f"Retrieved {len(events)} recent events")
            if len(events) > 0:
                logger.info(f"Most recent event date: {events[0].get('Event', {}).get('date', 'unknown')}")
        else:
            logger.warning("Unable to retrieve events or unexpected response format")
        
        # Test searching for attributes
        logger.info("Testing attribute search functionality...")
        attributes = misp.search(controller='attributes', type='ip-src', limit=5)
        
        if isinstance(attributes, list):
            logger.info(f"Retrieved {len(attributes)} IP attributes")
        else:
            logger.warning("Unable to retrieve attributes or unexpected response format")
        
        # Test retrieval of taxonomies
        logger.info("Testing taxonomies retrieval...")
        taxonomies = misp.taxonomies()
        
        if isinstance(taxonomies, list):
            logger.info(f"Retrieved {len(taxonomies)} taxonomies")
            taxonomy_names = [t.get('Taxonomy', {}).get('namespace') for t in taxonomies[:5]]
            logger.info(f"Sample taxonomies: {', '.join(taxonomy_names[:5]) if taxonomy_names else 'none'}")
        else:
            logger.warning("Unable to retrieve taxonomies or unexpected response format")
        
        # Create a test event object (but don't actually add it to MISP)
        logger.info("Testing event object creation (not adding to MISP)...")
        test_event = MISPEvent()
        test_event.info = f"TEST - MISP Connection Test - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        test_event.distribution = 0  # Your organization only
        test_event.threat_level_id = 4  # Undefined
        test_event.analysis = 0  # Initial
        
        logger.info(f"Test event object created with info: '{test_event.info}'")
        logger.info("✅ MISP connection test completed successfully!")
        
        return 0
    
    except ImportError as e:
        logger.error(f"❌ Failed to import PyMISP: {e}")
        logger.error("Please ensure PyMISP is installed: pip install pymisp")
        return 1
    except Exception as e:
        logger.error(f"❌ Connection failed: {str(e)}")
        
        # Provide guidance based on error type
        error_str = str(e).lower()
        if "ssl" in error_str or "certificate" in error_str:
            logger.error("SSL error detected. Try setting MISP_VERIFY_SSL=false in .env file")
            logger.error("For production use, configure proper SSL certificates")
        
        elif "unauthorized" in error_str or "403" in error_str or "401" in error_str:
            logger.error("Authentication failed. Check your MISP_KEY in .env file")
            logger.error("Ensure the API key has sufficient permissions")
        
        elif "connection" in error_str or "timed out" in error_str:
            logger.error("Connection error. Verify:")
            logger.error("1. The MISP server is accessible from this machine")
            logger.error("2. The URL is correct (including protocol http/https)")
            logger.error("3. No firewall is blocking the connection")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())