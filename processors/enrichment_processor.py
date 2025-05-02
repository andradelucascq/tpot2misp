"""
Enrichment processor for IoC data from various threat intelligence sources.
"""

import asyncio
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from abc import ABC, abstractmethod
from utils.logging import StructuredLogger
from utils.error_handling import handle_batch_error, retry_operation
from utils.validators import is_valid_ip, is_private_ip, is_reserved_ip, is_loopback_ip


class EnrichmentProvider(ABC):
    """Base class for all enrichment providers"""
    
    @abstractmethod
    async def enrich(self, indicator: str) -> Dict:
        """
        Enrich an indicator with threat intelligence
        
        Args:
            indicator: The indicator to enrich (usually an IP address)
            
        Returns:
            Dictionary containing enrichment data
        """
        pass


class VirusTotalEnricher(EnrichmentProvider):
    """VirusTotal enrichment provider"""
    
    def __init__(self, api_key: str):
        """
        Initialize the VirusTotal enricher
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.logger = StructuredLogger(name='virustotal_enricher')
        
    async def enrich(self, indicator: str) -> Dict:
        """
        Enrich an IP using VirusTotal
        
        Args:
            indicator: IP address to enrich
            
        Returns:
            Dictionary with enrichment results
        """
        # Validate IP format first
        if not is_valid_ip(indicator):
            self.logger.error(f"Invalid IP format for VirusTotal enrichment: {indicator}")
            return {
                'error': 'Invalid IP format',
                'is_valid': False,
                'reason': 'invalid_ip_format'
            }
            
        headers = {"x-apikey": self.api_key}
        try:
            response = await asyncio.to_thread(
                requests.get,
                f"{self.base_url}/ip_addresses/{indicator}",
                headers=headers,
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            
            # Extract meaningful data
            malicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            suspicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0)
            
            is_malicious = (malicious > 4 or suspicious > 8)
            
            return {
                'data': data,
                'is_valid': not is_malicious,
                'reason': 'malicious_ip' if is_malicious else None,
                'malicious_detections': malicious,
                'suspicious_detections': suspicious
            }
            
        except Exception as e:
            self.logger.error(f"Error enriching with VirusTotal: {str(e)}")
            return {
                'error': str(e),
                'is_valid': True  # Default to valid on error
            }


class AbuseIPDBEnricher(EnrichmentProvider):
    """AbuseIPDB enrichment provider"""
    
    def __init__(self, api_key: str):
        """
        Initialize the AbuseIPDB enricher
        
        Args:
            api_key: AbuseIPDB API key
        """
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.logger = StructuredLogger(name='abuseipdb_enricher')
        
    async def enrich(self, indicator: str) -> Dict:
        """
        Enrich an IP using AbuseIPDB
        
        Args:
            indicator: IP address to enrich
            
        Returns:
            Dictionary with enrichment results
        """
        # Validate IP format first
        if not is_valid_ip(indicator):
            self.logger.error(f"Invalid IP format for AbuseIPDB enrichment: {indicator}")
            return {
                'error': 'Invalid IP format',
                'is_valid': False, 
                'reason': 'invalid_ip_format'
            }
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            response = await asyncio.to_thread(
                requests.get,
                f"{self.base_url}/check",
                headers=headers,
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            
            is_malicious = False
            confidence_score = 0
            
            if 'data' in data and 'abuseConfidenceScore' in data['data']:
                confidence_score = data['data']['abuseConfidenceScore']
                is_malicious = confidence_score >= 80
                
            return {
                'data': data,
                'is_valid': not is_malicious,
                'reason': 'malicious_ip' if is_malicious else None,
                'confidence_score': confidence_score
            }
            
        except Exception as e:
            self.logger.error(f"Error enriching with AbuseIPDB: {str(e)}")
            return {
                'error': str(e),
                'is_valid': True  # Default to valid on error
            }


class GreyNoiseEnricher(EnrichmentProvider):
    """GreyNoise enrichment provider"""
    
    def __init__(self, api_key: str):
        """
        Initialize the GreyNoise enricher
        
        Args:
            api_key: GreyNoise API key
        """
        self.api_key = api_key
        self.base_url = "https://api.greynoise.io/v3/community"
        self.logger = StructuredLogger(name='greynoise_enricher')
        
    async def enrich(self, indicator: str) -> Dict:
        """
        Enrich an IP using GreyNoise
        
        Args:
            indicator: IP address to enrich
            
        Returns:
            Dictionary with enrichment results
        """
        # Validate IP format first
        if not is_valid_ip(indicator):
            self.logger.error(f"Invalid IP format for GreyNoise enrichment: {indicator}")
            return {
                'error': 'Invalid IP format',
                'is_valid': False,
                'reason': 'invalid_ip_format'
            }
            
        headers = {
            "key": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            response = await asyncio.to_thread(
                requests.get,
                f"{self.base_url}/{indicator}",
                headers=headers,
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            
            classification = data.get('classification', '')
            name = data.get('name', '').lower()
            tags = data.get('tags', [])
            
            is_scanner = any([
                classification == 'benign',
                name in ['shodan', 'censys', 'binaryedge'],
                any('scanner' in tag.lower() for tag in tags)
            ])
            
            return {
                'data': data,
                'is_valid': not is_scanner,
                'reason': 'known_scanner' if is_scanner else None,
                'classification': classification,
                'tags': tags
            }
            
        except Exception as e:
            self.logger.error(f"Error enriching with GreyNoise: {str(e)}")
            return {
                'error': str(e),
                'is_valid': True  # Default to valid on error
            }


class EnrichmentCache:
    """Cache for enrichment data with dynamic TTL"""
    
    def __init__(self, default_ttl: int = 3600, high_risk_ttl: int = 1800):
        """
        Initialize the enrichment cache
        
        Args:
            default_ttl: Default TTL for cache entries in seconds
            high_risk_ttl: TTL for high-risk indicators in seconds
        """
        self.cache: Dict[str, Tuple[Dict, datetime]] = {}
        self.default_ttl = default_ttl
        self.high_risk_ttl = high_risk_ttl
        self.logger = StructuredLogger(name='enrichment_cache')
    
    def get(self, key: str) -> Optional[Dict]:
        """
        Get a cached item if still valid
        
        Args:
            key: Cache key to retrieve
            
        Returns:
            Cached data if valid, None otherwise
        """
        if key not in self.cache:
            return None
        
        data, timestamp = self.cache[key]
        if datetime.now() - timestamp < timedelta(seconds=self._get_ttl(data)):
            return data
            
        return None
    
    def set(self, key: str, data: Dict) -> None:
        """
        Add an item to the cache
        
        Args:
            key: Cache key
            data: Data to cache
        """
        self.cache[key] = (data, datetime.now())
    
    def _get_ttl(self, data: Dict) -> int:
        """
        Calculate TTL based on enrichment results
        
        Args:
            data: Enrichment data
            
        Returns:
            TTL in seconds
        """
        try:
            # Check for high risk indicators that should expire sooner
            for provider_data in data.get('data', {}).values():
                if not provider_data.get('is_valid', True):
                    return self.high_risk_ttl
                    
            return self.default_ttl
            
        except Exception as e:
            self.logger.error(f"Error calculating TTL: {str(e)}")
            return self.default_ttl


class EnrichmentProcessor:
    """Processor for indicator enrichment"""
    
    def __init__(self, config: Dict[str, Any], metrics=None):
        """
        Initialize the enrichment processor
        
        Args:
            config: Configuration dictionary
            metrics: Optional metrics manager
        """
        self.config = config
        self.providers: List[EnrichmentProvider] = []
        self.cache = EnrichmentCache(
            default_ttl=config.get('cache_duration', 3600),
            high_risk_ttl=config.get('high_risk_cache_duration', 1800)
        )
        self.logger = StructuredLogger(name='enrichment_processor')
        self.metrics = metrics
        
        # Configure providers from config
        if config.get('enabled', False):
            self._setup_providers_from_config()
    
    def _setup_providers_from_config(self) -> None:
        """Configure enrichment providers from config"""
        providers_config = self.config.get('providers', {})
        
        if providers_config.get('virustotal', {}).get('enabled', False):
            api_key = providers_config['virustotal'].get('api_key', '')
            if api_key:
                self.add_provider(VirusTotalEnricher(api_key))
                self.logger.info("VirusTotal enrichment provider initialized")
                
        if providers_config.get('abuseipdb', {}).get('enabled', False):
            api_key = providers_config['abuseipdb'].get('api_key', '')
            if api_key:
                self.add_provider(AbuseIPDBEnricher(api_key))
                self.logger.info("AbuseIPDB enrichment provider initialized")
                
        if providers_config.get('greynoise', {}).get('enabled', False):
            api_key = providers_config['greynoise'].get('api_key', '')
            if api_key:
                self.add_provider(GreyNoiseEnricher(api_key))
                self.logger.info("GreyNoise enrichment provider initialized")
    
    def add_provider(self, provider: EnrichmentProvider) -> None:
        """
        Add an enrichment provider
        
        Args:
            provider: Provider instance to add
        """
        self.providers.append(provider)
    
    async def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an event with information from all providers
        
        Args:
            event: Event data containing the indicator
            
        Returns:
            Dictionary with enrichment results
        """
        result = {
            'should_process': True,
            'data': {}
        }
        
        indicator = event.get('source_ip')
        if not indicator:
            self.logger.warning("Enrichment failed: No source_ip in event")
            return result
        
        # Validate IP address format
        if not is_valid_ip(indicator):
            self.logger.warning(f"Invalid IP format: {indicator}")
            result['should_process'] = False
            result['reason'] = 'invalid_ip_format'
            return result
            
        # Check if IP is private, loopback, or reserved
        if is_private_ip(indicator):
            self.logger.info(f"Private IP detected: {indicator}")
            result['should_process'] = False
            result['reason'] = 'private_ip'
            result['data']['ip_validation'] = {'is_private': True}
            return result
            
        if is_loopback_ip(indicator):
            self.logger.info(f"Loopback IP detected: {indicator}")
            result['should_process'] = False
            result['reason'] = 'loopback_ip'
            result['data']['ip_validation'] = {'is_loopback': True}
            return result
            
        if is_reserved_ip(indicator):
            self.logger.info(f"Reserved IP detected: {indicator}")
            result['should_process'] = False
            result['reason'] = 'reserved_ip'
            result['data']['ip_validation'] = {'is_reserved': True}
            return result
        
        # Check cache
        cache_key = indicator
        cached_data = self.cache.get(cache_key)
        if cached_data:
            self.logger.debug(f"Using cached enrichment data for {indicator}")
            if self.metrics:
                self.metrics.increment_enrichment_cache_hits()
            return cached_data
            
        if self.metrics:
            self.metrics.increment_enrichment_cache_misses()
        
        # Add IP validation data to result
        result['data']['ip_validation'] = {
            'is_private': False,
            'is_loopback': False,
            'is_reserved': False
        }
        
        # Enrich with each provider
        provider_tasks = []
        for provider in self.providers:
            task = self._enrich_with_provider(provider, indicator)
            provider_tasks.append(task)
            
        # Process results in parallel
        if provider_tasks:
            provider_results = await asyncio.gather(*provider_tasks, return_exceptions=True)
            
            # Process results
            for provider_result in provider_results:
                if isinstance(provider_result, Exception):
                    self.logger.error(f"Error in enrichment: {str(provider_result)}")
                    continue
                    
                provider_name, enrichment_data = provider_result
                result['data'][provider_name] = enrichment_data
                
                # If any provider marks the indicator as invalid, we won't process it
                if not enrichment_data.get('is_valid', True):
                    result['should_process'] = False
                    result['reason'] = enrichment_data.get('reason')
        else:
            self.logger.info(f"No enrichment providers configured for {indicator}")
        
        # Store in cache
        self.cache.set(cache_key, result)
        return result
        
    async def _enrich_with_provider(self, provider: EnrichmentProvider, indicator: str) -> Tuple[str, Dict]:
        """
        Enrich with a single provider
        
        Args:
            provider: Provider to use for enrichment
            indicator: Indicator to enrich
            
        Returns:
            Tuple of (provider_name, enrichment_data)
        """
        provider_name = provider.__class__.__name__
        try:
            if self.metrics:
                self.metrics.increment_enrichment_requests(provider_name)
                
            enrichment_result = await provider.enrich(indicator)
            return (provider_name, enrichment_result)
                
        except Exception as e:
            self.logger.error(f"Error enriching with {provider_name}: {str(e)}")
            if self.metrics:
                self.metrics.increment_enrichment_errors(provider_name)
            return (provider_name, {"error": str(e), "is_valid": True}) 