#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Elasticsearch collector for T-Pot honeypot data in batch mode.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
from utils.logging import StructuredLogger
from utils.error_handling import handle_batch_error
from utils.validators import is_valid_ip, is_private_ip, is_reserved_ip, is_loopback_ip
from utils.elasticsearch_client import create_elasticsearch_client, ElasticClient
from config.settings import VALID_HONEYPOTS


class ElasticCollector:
    """Collector for T-Pot honeypot data from Elasticsearch"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Elasticsearch collector
        
        Args:
            config: Configuration dictionary with Elasticsearch settings
        """
        self.config = config
        self.es = create_elasticsearch_client(
            url=config['url'],
            username=config.get('user'),
            password=config.get('password'),
            verify_ssl=config.get('verify_ssl', False),
            timeout=config.get('timeout', 30)
        )
        
        self.logger = StructuredLogger(name='elastic_collector')
        
        # Por padrão, TODOS os honeypots devem ser consultados
        # Somente sobrescrever se o usuário explicitamente configurou uma lista não vazia
        # e essa lista possui honeypots válidos
        if isinstance(config.get('honeypots'), (list, str)) and config.get('honeypots'):
            # Process honeypots configuration - ensure it's a list of honeypot names
            if isinstance(config['honeypots'], str):
                self.honeypots = [hp.strip() for hp in config['honeypots'].split(',') if hp.strip()]
            else:
                self.honeypots = [hp.strip() for hp in config['honeypots'] if hp.strip()]
                
            # Verificar se a lista contém pelo menos um honeypot válido
            valid_configured_honeypots = [h for h in self.honeypots if h in VALID_HONEYPOTS]
            if valid_configured_honeypots:
                self.logger.info(f"Usando honeypots configurados pelo usuário: {', '.join(valid_configured_honeypots)}")
                self.honeypots = valid_configured_honeypots
            else:
                self.logger.info("Nenhum honeypot válido na configuração. Usando TODOS os honeypots suportados.")
                self.honeypots = list(VALID_HONEYPOTS)
        else:
            self.logger.info("Nenhum honeypot configurado. Usando TODOS os honeypots suportados.")
            self.honeypots = list(VALID_HONEYPOTS)
            
        self.lookback_days = config.get('lookback_days', 1)

    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect events from Elasticsearch for all configured honeypots
        
        Returns:
            List of honeypot events
        """
        all_events = []
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=self.lookback_days)
        
        self.logger.info(f"Collecting events from {start_time.isoformat()} to {end_time.isoformat()}")
        self.logger.info(f"Buscando eventos de {len(self.honeypots)} honeypots: {', '.join(self.honeypots)}")

        for honeypot in self.honeypots:
            try:
                events = self._collect_honeypot_events(honeypot, start_time, end_time)
                all_events.extend(events)
                self.logger.info(f"Collected {len(events)} events from honeypot {honeypot}")
            except Exception as e:
                handle_batch_error(self.logger, e, source=f"elasticsearch_{honeypot}")

        self.logger.info(f"Total events collected: {len(all_events)}")
        return all_events

    def _collect_honeypot_events(self, honeypot: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """
        Collect events for a specific honeypot type - usando consulta adaptada do projeto de referência
        
        Args:
            honeypot: Honeypot type to collect events for
            start_time: Start time for event collection
            end_time: End time for event collection
            
        Returns:
            List of events for the specified honeypot
        """
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time.isoformat(),
                                "lt": end_time.isoformat()
                            }
                        }
                    },
                    # Mais flexível - busca o tipo de honeypot em diferentes campos possíveis
                    {
                        "bool": {
                            "should": [
                                {"term": {"type": honeypot}},
                                {"term": {"sensor.type": honeypot}},
                                {"term": {"honeypot.type": honeypot}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }

        # Usar padrão de índice mais genérico para maior compatibilidade
        index_patterns = ["logstash-*", "*-*-*"]
        
        events = []
        for index_pattern in index_patterns:
            try:
                self.logger.info(f"Searching for {honeypot} events in index pattern: {index_pattern}")
                response = self.es.search(
                    index=index_pattern,
                    query=query,
                    size=10000,  # Maximum batch size
                    _source=["src_ip", "source_ip", "dst_ip", "destination_ip", "dst_port", 
                             "destination_port", "@timestamp", "type", "sensor.type", 
                             "honeypot.type", "geoip"]
                )
                
                # Process the hits
                hits = response.get('hits', {}).get('hits', [])
                self.logger.info(f"Found {len(hits)} {honeypot} events in {index_pattern}")
                
                for hit in hits:
                    source = hit.get('_source', {})
                    
                    # Obter IP de origem de diferentes campos possíveis
                    source_ip = source.get('src_ip') or source.get('source_ip')
                    
                    # Validar IP de origem
                    if not source_ip or not is_valid_ip(source_ip) or is_private_ip(source_ip) or is_reserved_ip(source_ip) or is_loopback_ip(source_ip):
                        continue
                    
                    # Obter IP e porta de destino de diferentes campos possíveis
                    destination_ip = source.get('dst_ip') or source.get('destination_ip')
                    destination_port = source.get('dst_port') or source.get('destination_port')
                    
                    event = {
                        'honeypot': honeypot,
                        'source_ip': source_ip,
                        'destination_ip': destination_ip,
                        'destination_port': destination_port,
                        'timestamp': source.get('@timestamp'),
                        'geo_location': source.get('geoip', {}),
                        'raw_data': source
                    }
                    events.append(event)
                
            except Exception as e:
                self.logger.warning(f"Error querying Elasticsearch for {honeypot} in {index_pattern}: {str(e)}")
                # Continua tentando outros padrões de índice
        
        if not events:
            self.logger.warning(f"No events found for honeypot {honeypot} in any index pattern")
            
        return events

    def cleanup(self) -> None:
        """Limpa recursos do coletor"""
        pass
