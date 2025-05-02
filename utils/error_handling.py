"""
Centralized error handling for tpot2misp.
"""

from typing import Dict, Any, Optional, Callable
import logging
import traceback
import asyncio


def handle_indicator_error(logger: logging.Logger, indicator: Dict[str, Any], error: Exception, metrics=None) -> bool:
    """
    Handle errors during indicator processing with appropriate logging and metrics.
    
    Args:
        logger: Logger instance
        indicator: The indicator data that caused the error
        error: The exception that was raised
        metrics: Optional metrics manager
        
    Returns:
        bool: False to indicate processing failed
    """
    source_ip = indicator.get('source_ip', 'N/A')
    honeypot = indicator.get('honeypot', 'unknown')
    
    # Removido parâmetro exc_info=True não suportado pelo StructuredLogger
    logger.error(
        f"Error processing indicator {source_ip} from {honeypot}: {str(error)}"
    )
    
    # Log do traceback completo manualmente
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    if metrics:
        metrics.increment_events_failed()
    
    return False


def handle_honeypot_error(logger: logging.Logger, honeypot: str, error: Exception, metrics=None, 
                          remaining_count: int = 0) -> bool:
    """
    Handle errors during honeypot batch processing with appropriate logging and metrics.
    
    Args:
        logger: Logger instance
        honeypot: The honeypot type
        error: The exception that was raised
        metrics: Optional metrics manager
        remaining_count: Number of indicators that failed due to this error
        
    Returns:
        bool: False to indicate processing failed
    """
    # Removida a opção exc_info=True que não é suportada pelo StructuredLogger
    logger.error(
        f"Critical error processing honeypot {honeypot}: {str(error)}"
    )
    
    # Log do traceback completo manualmente
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    if metrics and remaining_count > 0:
        for _ in range(remaining_count):
            metrics.increment_events_failed()
    
    return False


def handle_batch_error(logger: logging.Logger, error: Exception, source: str = "batch") -> bool:
    """
    Handle errors during batch operations with appropriate logging.
    
    Args:
        logger: Logger instance
        error: The exception that was raised
        source: Source of the error (e.g., "elasticsearch", "batch")
        
    Returns:
        bool: False to indicate processing failed
    """
    # Removida a opção exc_info=True que não é suportada pelo StructuredLogger
    logger.error(
        f"Critical error in {source} processing: {str(error)}"
    )
    
    # Log do traceback completo manualmente, se necessário
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    return False


async def retry_operation(operation: Callable, max_retries: int = 3, retry_delay: float = 5.0,
                   logger: Optional[logging.Logger] = None, 
                   error_handler: Optional[Callable] = None,
                   *args, **kwargs):
    """
    Retry an operation with exponential backoff.
    
    Args:
        operation: The function to retry
        max_retries: Maximum number of retry attempts
        retry_delay: Initial delay between retries (in seconds)
        logger: Optional logger for logging retry attempts
        error_handler: Optional error handler function
        args, kwargs: Arguments to pass to the operation
        
    Returns:
        Result of the operation or None if all retries failed
    """
    for attempt in range(max_retries):
        try:
            result = operation(*args, **kwargs)
            # Verificar se o resultado é uma coroutine
            if asyncio.iscoroutine(result):
                return await result
            return result
        except Exception as e:
            if logger:
                logger.warning(f"Attempt {attempt+1}/{max_retries} failed: {str(e)}")
                
            if attempt == max_retries - 1:
                if error_handler:
                    return error_handler(e)
                raise
                
            # Exponential backoff
            sleep_time = retry_delay * (2 ** attempt)
            await asyncio.sleep(sleep_time)
    
    return None