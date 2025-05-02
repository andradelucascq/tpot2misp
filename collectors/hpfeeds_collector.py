"""
HPFEEDS collector for real-time honeypot data.
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Callable
import hpfeeds
from utils.logging import StructuredLogger
from utils.error_handling import handle_indicator_error, handle_batch_error
from utils.validators import is_valid_ip, is_private_ip, is_reserved_ip, is_loopback_ip


class MessageBuffer:
    """Buffer for batching HPFEEDS messages"""
    
    def __init__(self, max_size: int = 1000, max_age: int = 300):
        """
        Initialize a message buffer
        
        Args:
            max_size: Maximum number of messages to buffer before processing
            max_age: Maximum age of messages in seconds before processing
        """
        self.max_size = max_size
        self.max_age = max_age
        self.messages: List[Dict] = []
        self.last_processed = 0.0
    
    def add(self, message: Dict) -> None:
        """Add a message to the buffer"""
        self.messages.append(message)
    
    def should_process(self) -> bool:
        """Check if the buffer should be processed"""
        try:
            # Use get_running_loop() instead of get_event_loop()
            current_time = asyncio.get_running_loop().time()
        except RuntimeError:
            # Fallback in case we're not in an event loop
            current_time = asyncio.new_event_loop().time()
            
        return (
            len(self.messages) >= self.max_size or
            (current_time - self.last_processed) >= self.max_age
        )
    
    def get_messages(self) -> List[Dict]:
        """Get all messages and clear the buffer"""
        messages = self.messages.copy()
        self.messages.clear()
        try:
            # Use get_running_loop() instead of get_event_loop()
            self.last_processed = asyncio.get_running_loop().time()
        except RuntimeError:
            # Fallback in case we're not in an event loop
            self.last_processed = asyncio.new_event_loop().time()
        return messages
    
    def size(self) -> int:
        """Get the current size of the buffer"""
        return len(self.messages)


class HPFeedsCollector:
    """Collector for HPFEEDS data in realtime mode"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the HPFEEDS collector
        
        Args:
            config: Configuration dictionary for HPFEEDS
        """
        self.host = config['host']
        self.port = config['port']
        self.ident = config['ident']
        self.secret = config['secret']
        self.channels = config['channels']
        self.use_tls = config.get('use_tls', False)
        self.tls_cert = config.get('tls_cert')
        self.tls_key = config.get('tls_key')
        
        self.client = None
        self.buffer = MessageBuffer()
        self.callback = None
        self.logger = StructuredLogger(name='hpfeeds_collector')
        self.metrics = None
        
        # Add counters for IP validation stats
        self.filtered_ips = 0
        self.last_stats_time = 0
        self.stats_interval = 300  # Log stats every 5 minutes
    
    def set_metrics(self, metrics_manager) -> None:
        """Set the metrics manager"""
        self.metrics = metrics_manager
    
    async def connect(self) -> bool:
        """
        Establish connection to HPFEEDS broker
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.client = hpfeeds.new(
                host=self.host,
                port=self.port,
                ident=self.ident,
                secret=self.secret,
                ssl=self.use_tls,
                cert_path=self.tls_cert
            )
            
            if self.metrics:
                self.metrics.set_hpfeeds_connection_status(True)
                
            self.logger.info(f"Connected to HPFEEDS broker at {self.host}:{self.port}")
            
            for channel in self.channels:
                self.client.subscribe(channel)
                self.logger.info(f"Subscribed to channel: {channel}")
                
            self.client.on_message = self.on_message_wrapper
            return True
            
        except Exception as e:
            if self.metrics:
                self.metrics.set_hpfeeds_connection_status(False)
            handle_batch_error(self.logger, e, source="hpfeeds_connection")
            return False
    
    async def process_batch(self) -> None:
        """Process a batch of messages"""
        if not self.buffer.should_process() or not self.callback:
            return
        
        messages = self.buffer.get_messages()
        if self.metrics:
            self.metrics.set_batch_size(len(messages))
        
        try:
            try:
                # Use get_running_loop() instead of get_event_loop()
                start_time = asyncio.get_running_loop().time()
            except RuntimeError:
                # Fallback in case we're not in an event loop
                start_time = asyncio.new_event_loop().time()
            
            # Pass the batch to the callback for processing
            await self.callback(messages)
            
            try:
                # Use get_running_loop() instead of get_event_loop()
                duration = asyncio.get_running_loop().time() - start_time
            except RuntimeError:
                # Fallback in case we're not in an event loop
                duration = asyncio.new_event_loop().time() - start_time
                
            if self.metrics:
                self.metrics.observe_batch_processing_time(duration)
                
        except Exception as e:
            handle_batch_error(self.logger, e, source="hpfeeds_batch")
    
    def on_message_wrapper(self, identifier: str, channel: str, payload: bytes) -> None:
        """Wrapper for HPFEEDS message callback"""
        asyncio.create_task(self.on_message(channel, payload))
    
    async def on_message(self, channel: str, payload: bytes) -> None:
        """
        Handle incoming HPFEEDS messages with IP validation
        
        Args:
            channel: HPFEEDS channel name
            payload: Message payload
        """
        try:
            message = json.loads(payload.decode('utf-8'))
            if self.metrics:
                self.metrics.increment_hpfeeds_messages()
            
            # Extract and validate source IP
            source_ip = message.get('src_ip')
            if not source_ip:
                return  # Skip messages without source IP
                
            # Perform IP validation
            if not self._validate_ip(source_ip):
                self.filtered_ips += 1
                self._maybe_log_stats()  # Log periodic stats
                return
                
            # Add validation status to the message
            message['ip_validation'] = {
                'is_valid': True,
                'is_private': False,
                'is_loopback': False,
                'is_reserved': False
            }
            
            if self.buffer.size() < self.buffer.max_size:
                self.buffer.add(message)
                await self.process_batch()
            else:
                self.logger.warning("Buffer is full, dropping message")
                
        except json.JSONDecodeError:
            self.logger.error("Failed to decode message from HPFEEDS")
        except Exception as e:
            self.logger.error(f"Error processing HPFEEDS message: {str(e)}")

    def _validate_ip(self, ip_str: str) -> bool:
        """
        Validate an IP address against multiple criteria
        
        Args:
            ip_str: IP address to validate
            
        Returns:
            bool: True if IP is valid and allowed, False otherwise
        """
        try:
            if not is_valid_ip(ip_str):
                self.logger.debug(f"Filtered invalid IP format: {ip_str}")
                return False
                
            if is_private_ip(ip_str):
                self.logger.debug(f"Filtered private IP: {ip_str}")
                return False
                
            if is_loopback_ip(ip_str):
                self.logger.debug(f"Filtered loopback IP: {ip_str}")
                return False
                
            if is_reserved_ip(ip_str):
                self.logger.debug(f"Filtered reserved IP: {ip_str}")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating IP {ip_str}: {str(e)}")
            return False

    def _maybe_log_stats(self) -> None:
        """Log IP validation statistics periodically"""
        try:
            # Use get_running_loop() instead of get_event_loop()
            current_time = asyncio.get_running_loop().time()
        except RuntimeError:
            # Fallback in case we're not in an event loop
            current_time = asyncio.new_event_loop().time()
            
        if current_time - self.last_stats_time >= self.stats_interval:
            self.logger.info(f"IP validation stats - Filtered IPs: {self.filtered_ips}")
            if self.metrics:
                self.metrics.set_filtered_ips(self.filtered_ips)
            self.filtered_ips = 0  # Reset counter
            self.last_stats_time = current_time

    async def collect(self, callback: Callable) -> None:
        """
        Connect to HPFEEDS and process events via callback
        
        Args:
            callback: Function to call when events are received
        """
        self.callback = callback
        
        while True:
            try:
                if not self.client or not self.client.connected:
                    connected = await self.connect()
                    if not connected:
                        await asyncio.sleep(5)  # Wait before retry
                        continue
                
                await asyncio.sleep(1)
                await self.process_batch()
                
            except Exception as e:
                self.logger.error(f"Error in HPFEEDS collector: {str(e)}")
                await asyncio.sleep(5)  # Wait before retry 