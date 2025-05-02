import json
import logging
import os
import traceback
from logging import handlers
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pythonjsonlogger import jsonlogger

class StructuredLogger:
    """Logger estruturado com suporte a formato JSON e estatísticas"""
    
    def __init__(self, name: str = 'tpot2misp', level: str = 'INFO', 
                 file_config: Optional[Dict[str, Any]] = None):
        """Inicializa o logger estruturado
        
        Args:
            name: Nome do logger
            level: Nível de log (INFO, DEBUG, etc)
            file_config: Configuração do arquivo de log
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.propagate = False
        
        # Limpar handlers existentes
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # Formatter JSON
        json_formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(json_formatter)
        self.logger.addHandler(console_handler)
        
        # File Handler (opcional)
        if file_config and file_config.get('enabled', False):
            log_path = file_config.get('path', 'logs/tpot2misp.log')
            
            # Garantir que o diretório existe
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            
            file_handler = handlers.RotatingFileHandler(
                log_path,
                maxBytes=file_config.get('max_size', 10485760),
                backupCount=file_config.get('backup_count', 5)
            )
            file_handler.setFormatter(json_formatter)
            self.logger.addHandler(file_handler)
    
    def _format_message(self, message: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Formata a mensagem de log com contexto adicional"""
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'message': message
        }
        
        if extra:
            log_data.update(extra)
            
        return log_data
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Registra um log de nível INFO"""
        self.logger.info(message, extra=extra)
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Registra um log de nível ERROR"""
        self.logger.error(message, extra=extra)
    
    def exception(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Registra um log de nível ERROR com informações da exceção atual
        
        Este método deve ser chamado a partir de um bloco except.
        Registra automaticamente o traceback completo da exceção.
        """
        exception_info = {
            'exception_traceback': traceback.format_exc()
        }
        
        if extra:
            exception_info.update(extra)
            
        self.logger.error(message, exc_info=True, extra=exception_info)
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Registra um log de nível WARNING"""
        self.logger.warning(message, extra=extra)
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Registra um log de nível DEBUG"""
        self.logger.debug(message, extra=extra)
    
    def critical(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Registra um log de nível CRITICAL"""
        self.logger.critical(message, extra=extra)
    
    def log_statistics(self, stats: Dict[str, Any]) -> None:
        """Registra estatísticas de processamento"""
        self.info("Processing statistics", extra={"stats": stats})
    
    def log_batch_summary(self, total_events: int, processed_events: int, stats_by_honeypot: Dict[str, int]) -> None:
        """Registra resumo do processamento em batch"""
        self.info("Batch processing summary", extra={
            "total_events": total_events,
            "processed_events": processed_events,
            "stats_by_honeypot": stats_by_honeypot,
            "success_rate": (processed_events / total_events) * 100 if total_events > 0 else 0
        })
