"""
Métricas para monitoramento da integração T-Pot to MISP
"""

from prometheus_client import Counter, Gauge, Histogram, start_http_server
from typing import Dict, Any, Optional
import logging

class MetricsManager:
    """Gerenciador de métricas para monitoramento da integração"""
    
    def __init__(self, port: int = 9431):
        """Inicializa o gerenciador de métricas
        
        Args:
            port: Porta para servidor HTTP Prometheus
        """
        self.port = port
        self.logger = logging.getLogger('tpot2misp')
        
        # Métricas de eventos
        self.events_processed = Counter(
            'tpot2misp_events_processed_total',
            'Total de eventos processados'
        )
        self.events_failed = Counter(
            'tpot2misp_events_failed_total',
            'Total de eventos com falha de processamento'
        )
        self.events_by_honeypot = Counter(
            'tpot2misp_events_by_honeypot_total',
            'Total de eventos por tipo de honeypot',
            ['honeypot']
        )
        
        # Métricas de enriquecimento
        self.enrichment_requests = Counter(
            'tpot2misp_enrichment_requests_total',
            'Total de requisições de enriquecimento',
            ['provider']
        )
        self.enrichment_errors = Counter(
            'tpot2misp_enrichment_errors_total',
            'Total de erros de enriquecimento',
            ['provider']
        )
        self.enrichment_cache_hits = Counter(
            'tpot2misp_enrichment_cache_hits_total',
            'Total de acertos de cache de enriquecimento'
        )
        
        # Métricas de HPFEEDS (modo realtime)
        self.hpfeeds_messages = Counter(
            'tpot2misp_hpfeeds_messages_total',
            'Total de mensagens recebidas via HPFEEDS'
        )
        self.hpfeeds_connection = Gauge(
            'tpot2misp_hpfeeds_connection',
            'Status de conexão HPFEEDS (1=conectado, 0=desconectado)'
        )
        
        # Métricas de batch
        self.batch_size = Gauge(
            'tpot2misp_batch_size',
            'Tamanho do último lote processado'
        )
        self.batch_duration = Histogram(
            'tpot2misp_batch_duration_seconds',
            'Duração do processamento de lotes',
            buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0]
        )
    
    def start(self) -> None:
        """Inicia o servidor HTTP para métricas Prometheus"""
        try:
            start_http_server(self.port)
            self.logger.info(f"Servidor de métricas Prometheus iniciado na porta {self.port}")
        except Exception as e:
            self.logger.error(f"Erro ao iniciar servidor de métricas: {str(e)}")
    
    # Métodos para incrementar contadores
    
    def increment_events_processed(self) -> None:
        """Incrementa contador de eventos processados"""
        self.events_processed.inc()
    
    def increment_events_failed(self) -> None:
        """Incrementa contador de eventos com falha"""
        self.events_failed.inc()
    
    def increment_events_by_honeypot(self, honeypot: str) -> None:
        """Incrementa contador de eventos por tipo de honeypot"""
        self.events_by_honeypot.labels(honeypot=honeypot).inc()
    
    def increment_enrichment_requests(self, provider: str) -> None:
        """Incrementa contador de requisições de enriquecimento"""
        self.enrichment_requests.labels(provider=provider).inc()
    
    def increment_enrichment_errors(self, provider: str) -> None:
        """Incrementa contador de erros de enriquecimento"""
        self.enrichment_errors.labels(provider=provider).inc()
    
    def increment_enrichment_cache_hits(self) -> None:
        """Incrementa contador de acertos de cache"""
        self.enrichment_cache_hits.inc()
    
    def increment_hpfeeds_messages(self) -> None:
        """Incrementa contador de mensagens HPFEEDS"""
        self.hpfeeds_messages.inc()
    
    # Métodos para configurar gauges
    
    def set_hpfeeds_connection(self, connected: bool) -> None:
        """Define status de conexão HPFEEDS"""
        self.hpfeeds_connection.set(1 if connected else 0)
    
    def set_batch_size(self, size: int) -> None:
        """Define tamanho do lote atual"""
        self.batch_size.set(size)
    
    # Context manager para medir duração de operações
    
    def time_batch_processing(self):
        """Context manager para medir tempo de processamento de lote"""
        return self.batch_duration.time()