#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
T-Pot to MISP Integration
Main entry point for the integration between T-Pot honeypots and MISP.
"""

import asyncio
import sys
import time
from datetime import datetime, timedelta
from collectors.elastic_collector import ElasticCollector
from collectors.hpfeeds_collector import HPFeedsCollector
from processors.misp_processor import MISPProcessor
from processors.enrichment_processor import EnrichmentProcessor
from utils.metrics import MetricsManager
from utils.logging import StructuredLogger
from utils.error_handling import handle_batch_error
from config.settings import (
    COLLECTION_CONFIG,
    MISP_CONFIG,
    ENRICHMENT_CONFIG,
    METRICS_CONFIG,
    LOGGING_CONFIG,
    HPFEEDS_CONFIG
)


class TpotMispIntegrator:
    """Main integrator class between T-Pot and MISP"""
    
    def __init__(self):
        """Initialize the integrator with required services"""
        # Initialize logging
        self.logger = StructuredLogger(
            name='tpot2misp',
            level=LOGGING_CONFIG['level'],
            file_config=LOGGING_CONFIG['file']
        )
        
        self.logger.info("Initializing T-Pot to MISP integration")
        
        # Initialize metrics ONLY if enabled AND in realtime mode
        self.metrics = None
        if COLLECTION_CONFIG['mode'] == 'realtime' and METRICS_CONFIG['enabled']:
            self.logger.info("Prometheus metrics enabled and will be started (realtime mode)")
            self.metrics = MetricsManager(port=METRICS_CONFIG['port'])
            self.metrics.start()
        elif METRICS_CONFIG['enabled']:
            self.logger.info("Prometheus metrics globally enabled, but will not be started (batch mode)")
        else:
            self.logger.info("Prometheus metrics disabled")
        
        # Initialize enrichment processor
        self.enrichment_processor = None
        if ENRICHMENT_CONFIG['enabled']:
            self.enrichment_processor = EnrichmentProcessor(
                ENRICHMENT_CONFIG,
                metrics=self.metrics
            )
            self.logger.info("Enrichment processor initialized")
        
        # Initialize MISP processor
        self.misp_processor = MISPProcessor(MISP_CONFIG)
    
    async def run_batch_mode(self):
        """Run the integration in batch mode"""
        self.logger.info("Starting batch collection mode")
        collector = ElasticCollector(COLLECTION_CONFIG['batch'])
        
        try:
            # Collect events from Elasticsearch
            events = collector.collect()
            if not events:
                self.logger.info("No new events to process")
                return
                
            self.logger.info(f"Collected {len(events)} events in batch mode")
            
            # Agrupar eventos por tipo de honeypot
            events_by_honeypot = {}
            for event in events:
                honeypot = event.get('honeypot', 'unknown')
                if honeypot not in events_by_honeypot:
                    events_by_honeypot[honeypot] = []
                events_by_honeypot[honeypot].append(event)
            
            # Processar um honeypot por vez
            total_processed = 0
            for honeypot, honeypot_events in events_by_honeypot.items():
                self.logger.info(f"Processando {len(honeypot_events)} eventos do honeypot {honeypot}")
                
                try:
                    # Processar eventos para este honeypot específico
                    processed = await self.misp_processor.process_honeypot_events(
                        honeypot,
                        honeypot_events,
                        enrichment_processor=self.enrichment_processor,
                        metrics=self.metrics
                    )
                    
                    self.logger.info(f"Processados com sucesso {processed} de {len(honeypot_events)} eventos do honeypot {honeypot}")
                    total_processed += processed
                    
                except Exception as e:
                    self.logger.error(f"Erro ao processar eventos do honeypot {honeypot}: {str(e)}")
                    # Continue com o próximo honeypot mesmo se este falhar
            
            self.logger.info(f"Successfully processed {total_processed} total events")
            
            # Após o processamento, gerar relatório
            if self.misp_processor.validation_report:
                report_path = self.misp_processor.validation_report.generate_report()
                self.logger.info(f"Relatório de validação gerado: {report_path}")
            
        except Exception as e:
            handle_batch_error(self.logger, e, source="batch_mode")
    
    async def process_hpfeeds_events(self, events):
        """
        Process events received from HPFEEDS
        
        Args:
            events: List of events from HPFEEDS
        """
        try:
            self.logger.info(f"Processing {len(events)} events from HPFEEDS")
            processed = await self.misp_processor.process_events_batch(
                events,
                enrichment_processor=self.enrichment_processor,
                metrics=self.metrics
            )
            self.logger.info(f"Successfully processed {processed} events from HPFEEDS")
        except Exception as e:
            handle_batch_error(self.logger, e, source="hpfeeds_batch")
    
    async def run_realtime_mode(self):
        """Run the integration in realtime mode"""
        self.logger.info("Starting realtime collection mode")
        
        try:
            collector = HPFeedsCollector(HPFEEDS_CONFIG)
            if self.metrics:
                collector.set_metrics(self.metrics)
                
            await collector.collect(self.process_hpfeeds_events)
            
        except Exception as e:
            handle_batch_error(self.logger, e, source="realtime_mode")
    
    async def run(self):
        """Run the integration in the configured mode"""
        try:
            self.logger.info(f"Starting T-Pot to MISP integration in {COLLECTION_CONFIG['mode']} mode")
            
            if COLLECTION_CONFIG['mode'] == 'batch':
                interval_hours = COLLECTION_CONFIG['batch'].get('interval_hours', 0)
                
                if interval_hours > 0:
                    # Modo batch com execução periódica
                    self.logger.info(f"Batch mode configured to run every {interval_hours} hour(s)")
                    
                    while True:
                        run_start_time = datetime.now()
                        self.logger.info(f"Starting batch collection at {run_start_time}")
                        
                        # Executa o processamento batch
                        await self.run_batch_mode()
                        
                        # Calcula tempo até próxima execução
                        next_run = run_start_time + timedelta(hours=interval_hours)
                        now = datetime.now()
                        seconds_until_next_run = max(0, (next_run - now).total_seconds())
                        
                        if seconds_until_next_run > 0:
                            self.logger.info(f"Batch processing completed. Next run scheduled at {next_run} (in {seconds_until_next_run:.0f} seconds)")
                            await asyncio.sleep(seconds_until_next_run)
                        else:
                            self.logger.warning("Batch processing took longer than interval. Starting next run immediately.")
                else:
                    # Modo batch com execução única
                    self.logger.info("Batch mode configured to run once and exit")
                    await self.run_batch_mode()
                    self.logger.info("Batch processing completed. Exiting.")
                    return  # Sai do método, o que encerra o programa
                    
            elif COLLECTION_CONFIG['mode'] == 'realtime':
                await self.run_realtime_mode()
            else:
                self.logger.error(f"Invalid collection mode configured: {COLLECTION_CONFIG['mode']}")
                sys.exit(1)
                
        except KeyboardInterrupt:
            self.logger.info("Shutting down by user request (KeyboardInterrupt)")
        except Exception as e:
            # Usando logger.exception que já inclui o traceback automaticamente
            self.logger.exception(f"Fatal error in main process: {e}")
        finally:
            if self.metrics:
                self.logger.info("Stopping Prometheus metrics server")
                self.metrics.stop()
            self.logger.info("T-Pot to MISP integration finished")


async def main():
    """Main entry point"""
    integrator = TpotMispIntegrator()
    await integrator.run()


if __name__ == '__main__':
    asyncio.run(main())