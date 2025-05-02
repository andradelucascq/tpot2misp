"""
MISP processor for handling interactions with MISP platform.
"""

import traceback
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Set
from utils.logging import StructuredLogger
from utils.error_handling import handle_indicator_error, handle_honeypot_error
from utils.validation_report import ValidationReportGenerator


class MISPProcessor:
    """Handles interactions with the MISP platform"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the MISP processor
        
        Args:
            config: Configuration dictionary with MISP settings
        """
        self.misp = ExpandedPyMISP(
            config['url'],
            config['key'],
            config.get('verify_ssl', False)
        )
        self.auto_publish = config.get('auto_publish', False)
        self.publish_delay = config.get('publish_delay', 3600)
        self.threat_level = config.get('threat_level', 2)
        self.analysis = config.get('analysis', 1)
        self.distribution = config.get('distribution', 0)
        self.logger = StructuredLogger(name='misp_processor')
        self.logger.info(f"MISP processor initialized: {config['url']}")
        
        # Cache global para evitar processamento repetido dos mesmos IPs
        # Formato: {"honeypot_type": set(["ip1", "ip2", ...])}
        self.processed_ips = {}
        self.validation_report = None
        if config.get('VALIDATION_REPORT_ENABLED', True):
            self.validation_report = ValidationReportGenerator(config)
    
    async def get_or_create_daily_event(self, honeypot: str) -> Optional[str]:
        """
        Get or create a daily event for the specified honeypot with the original title format
        
        Args:
            honeypot: Honeypot type to get or create an event for
            
        Returns:
            Event UUID if successful, None otherwise
        """
        # Formato do título
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        event_info = f"T-Pot {honeypot} - Events detected on {today}"

        # Search for existing event first
        try:
            result = self.misp.search_index(
                eventinfo=event_info,
                date_from=datetime.now(timezone.utc).strftime('%Y-%m-%d')
            )

            if result:
                self.logger.info(f"Found existing event for {honeypot}: {result[0]['uuid']}")
                return result[0]['uuid']
        except Exception as e:
            self.logger.error(f"Error searching for MISP event: {str(e)}")
            return None

        # Create new event if not found
        try:
            event = MISPEvent()
            event.info = event_info
            event.threat_level_id = self.threat_level
            event.analysis = self.analysis
            event.distribution = self.distribution
            
            created_event = self.misp.add_event(event, pythonify=True)
            self.logger.info(f"Created new event for {honeypot}: {created_event.uuid}")
            return created_event.uuid
        except Exception as e:
            self.logger.error(f"Error creating MISP event for {honeypot}: {str(e)}")
            return None

    async def add_indicator_to_event(self, event_id: str, indicator: Dict[str, Any]) -> bool:
        """
        Add an indicator to a MISP event - simplificado conforme implementação de referência
        
        Args:
            event_id: UUID of the MISP event
            indicator: Indicator data to add
            
        Returns:
            True if successful, False otherwise
        """
        try:
            source_ip = indicator.get('source_ip')
            honeypot_type = indicator.get('honeypot', 'unknown')
            
            if not source_ip:
                self.logger.warning("Indicator missing source_ip, skipping")
                return False
            
            # Verificar se já processamos este IP para este tipo de honeypot
            if honeypot_type not in self.processed_ips:
                self.processed_ips[honeypot_type] = set()
                
            # Se o IP já foi processado, pule sem gerar logs adicionais
            if source_ip in self.processed_ips[honeypot_type]:
                return True
            
            # Verificar se o IP já existe no evento
            try:
                event = self.misp.get_event(event_id, pythonify=True)
                if not event:
                    self.logger.error(f"Event {event_id} not found")
                    return False
                    
                # Verificar atributos existentes
                for attr in event.attributes:
                    if attr.type == 'ip-src' and attr.value == source_ip:
                        # Adicionar ao cache para evitar verificações futuras
                        self.processed_ips[honeypot_type].add(source_ip)
                        self.logger.info(f"IP {source_ip} already exists in event {event_id}, skipping")
                        return True
                        
            except Exception as e:
                self.logger.warning(f"Error checking existing attributes: {str(e)}")
                
            # Adicionar o atributo usando o formato simplificado.
            attribute = MISPAttribute()
            attribute.type = 'ip-src'
            attribute.category = 'Network activity'
            attribute.value = source_ip
            attribute.to_ids = False
            
            # Adicionar o atributo diretamente ao evento usando método que não requer tags separadas
            result = self.misp.add_attribute(event_id, attribute, pythonify=True)
            
            # Adicionar ao cache para evitar verificações futuras
            self.processed_ips[honeypot_type].add(source_ip)
            
            # Adicionar tags diretamente nos parâmetros, evitando chamadas separadas que podem falhar
            try:
                # Obter o ID do atributo criado
                if hasattr(result, 'id'):
                    attr_id = result.id
                    # Adicionar as tags usando o método tag_edit que é mais robusto
                    self.misp.tag_edit({"uuid": attr_id, "tag": "tlp:amber"})
                    self.misp.tag_edit({"uuid": attr_id, "tag": f"honeypot:{honeypot_type}"})
                    
                    # Adicionar tag correlate
                    # Descomente a linha abaixo para permitir correlações automáticas entre eventos
                    # self.misp.tag_edit({"uuid": attr_id, "tag": "correlate"})
            except Exception as tag_error:
                # Se falhar ao adicionar tags, log o erro mas considere o indicador como adicionado
                self.logger.warning(f"Error adding tags to attribute {source_ip}: {str(tag_error)}")
            
            self.logger.info(f"Added indicator {source_ip} to event {event_id}")
            return True
                
        except Exception as e:
            return handle_indicator_error(
                self.logger, 
                indicator, 
                e
            )

    async def publish_event(self, event_id: str, alert: bool = False) -> bool:
        """
        Publish a MISP event
        
        Args:
            event_id: UUID of the MISP event
            alert: Whether to trigger alerts
            
        Returns:
            True if successful, False otherwise
        """
        try:
            event = self.misp.get_event(event_id)
            if not event:
                self.logger.error(f"Event {event_id} not found")
                return False

            self.misp.publish(event, alert)
            self.logger.info(f"Event {event_id} published successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error publishing event {event_id}: {str(e)}")
            return False
            
    async def process_events_batch(self, events: List[Dict[str, Any]], enrichment_processor=None, 
                                  metrics=None) -> int:
        """
        Process a batch of events, with optional enrichment
        
        Args:
            events: List of events to process
            enrichment_processor: Optional enrichment processor
            metrics: Optional metrics manager
            
        Returns:
            Number of successfully processed events
        """
        if not events:
            self.logger.info("No events to process")
            return 0
            
        processed = 0
        events_by_honeypot = {}
        
        # Group events by honeypot
        for event in events:
            honeypot = event.get('honeypot', 'unknown')
            if honeypot not in events_by_honeypot:
                events_by_honeypot[honeypot] = []
            events_by_honeypot[honeypot].append(event)
            
        # Process events by honeypot
        for honeypot, honeypot_events in events_by_honeypot.items():
            event_id = None
            try:
                # Get or create MISP event for the honeypot
                event_id = await self.get_or_create_daily_event(honeypot)
                if not event_id:
                    self.logger.warning(f"Could not get or create MISP event for {honeypot}. Skipping events.")
                    continue
                
                initial_processed_count = processed
                
                # Process each indicator
                for event in honeypot_events:
                    try:
                        # Enrich event if configured
                        if enrichment_processor and 'source_ip' in event and event['source_ip']:
                            event['enrichment'] = await enrichment_processor.enrich(event)
                        
                        # Validate enrichment result
                        should_process = True
                        if 'enrichment' in event:
                            should_process = event['enrichment'].get('should_process', True)
                            
                        # Add to MISP if passed enrichment validation
                        if should_process:
                            if await self.add_indicator_to_event(event_id, event):
                                processed += 1
                                if metrics:
                                    metrics.increment_events_processed()
                            else:
                                if metrics:
                                    metrics.increment_events_failed()
                        else:
                            self.logger.info(f"Indicator {event.get('source_ip', 'N/A')} skipped due to enrichment rules")
                    
                    except Exception as indicator_error:
                        handle_indicator_error(self.logger, event, indicator_error, metrics)
                
            except Exception as e:
                remaining_in_batch = len(honeypot_events) - (processed - initial_processed_count)
                handle_honeypot_error(self.logger, honeypot, e, metrics, remaining_in_batch)
                
        self.logger.info(f"Processed {processed} of {len(events)} events in this batch")
        return processed
    
    async def process_honeypot_events(self, honeypot: str, events: List[Dict[str, Any]], 
                            enrichment_processor=None, metrics=None) -> int:
        """
        Processa eventos de um único tipo de honeypot, garantindo separação entre diferentes honeypots
        
        Args:
            honeypot: Tipo de honeypot dos eventos
            events: Lista de eventos a processar
            enrichment_processor: Opcional processador de enriquecimento
            metrics: Opcional gerenciador de métricas
            
        Returns:
            Número de eventos processados com sucesso
        """
        if not events:
            self.logger.info(f"Sem eventos para processar do honeypot {honeypot}")
            return 0
            
        processed = 0
        event_id = None
        
        try:
            # Obter ou criar evento MISP para o honeypot
            event_id = await self.get_or_create_daily_event(honeypot)
            if not event_id:
                self.logger.warning(f"Não foi possível obter ou criar evento MISP para {honeypot}. Ignorando eventos.")
                return 0
            
            # Processar cada indicador
            for event in events:
                try:
                    # Garantir que o evento tenha o tipo de honeypot correto
                    event['honeypot'] = honeypot
                    
                    # Enriquecer evento se configurado
                    if enrichment_processor and 'source_ip' in event and event['source_ip']:
                        event['enrichment'] = await enrichment_processor.enrich(event)
                    
                    # Validar resultado do enriquecimento
                    should_process = True
                    if 'enrichment' in event:
                        should_process = event['enrichment'].get('should_process', True)
                        
                    # Adicionar ao MISP se passou na validação de enriquecimento
                    if should_process:
                        if await self.add_indicator_to_event(event_id, event):
                            processed += 1
                            if metrics:
                                metrics.increment_events_processed()
                        else:
                            if metrics:
                                metrics.increment_events_failed()
                    else:
                        self.logger.info(f"Indicador {event.get('source_ip', 'N/A')} ignorado devido às regras de enriquecimento")
                
                except Exception as indicator_error:
                    handle_indicator_error(self.logger, event, indicator_error, metrics)
            
            # Publicar o evento se auto_publish estiver habilitado
            if self.auto_publish and processed > 0:
                self.logger.info(f"Auto-publicando evento {event_id} para honeypot {honeypot}")
                await self.publish_event(event_id)
                
        except Exception as e:
            handle_honeypot_error(self.logger, honeypot, e, metrics, len(events) - processed)
            
        self.logger.info(f"Processados {processed} de {len(events)} eventos do honeypot {honeypot}")
        return processed
