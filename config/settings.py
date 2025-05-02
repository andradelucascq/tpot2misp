#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration management for T-Pot to MISP integration.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
from typing import Dict, Any

# Load environment variables
load_dotenv()

def _get_env_bool(key: str, default: bool = False) -> bool:
    """Helper to get boolean from environment variable"""
    return os.getenv(key, str(default)).lower() == 'true'

def _get_env_int(key: str, default: int) -> int:
    """Helper to get integer from environment variable"""
    return int(os.getenv(key, default))

# Collection Configuration
COLLECTION_CONFIG = {
    'mode': os.getenv('COLLECTION_MODE', 'batch'),
    'batch': {
        'url': os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200'),
        'user': os.getenv('ELASTICSEARCH_USER', 'elastic'),
        'password': os.getenv('ELASTICSEARCH_PASSWORD', 'changeme'),
        'verify_ssl': os.getenv('ELASTICSEARCH_VERIFY_SSL', 'false').lower() == 'true',
        'honeypots': os.getenv('TPOT_HONEYPOTS', 'cowrie,dionaea').split(','),
        'lookback_days': int(os.getenv('LOOKBACK_DAYS', '1')),
        'interval_hours': int(os.getenv('BATCH_INTERVAL_HOURS', '0'))  # 0 = executar uma vez e sair
    }
}

# MISP Configuration
MISP_CONFIG = {
    'url': os.getenv('MISP_URL', 'https://localhost'),
    'key': os.getenv('MISP_KEY', 'your-misp-key'),
    'verify_ssl': os.getenv('MISP_VERIFY_SSL', 'false').lower() == 'true',
    'auto_publish': os.getenv('AUTO_PUBLISH', 'false').lower() == 'true',
    'publish_delay': int(os.getenv('PUBLISH_DELAY', '3600')),
    'threat_level': int(os.getenv('MISP_THREAT_LEVEL', '2')),
    'analysis': int(os.getenv('MISP_ANALYSIS', '1')),
    'distribution': int(os.getenv('MISP_DISTRIBUTION', '0'))
}

# Enrichment Configuration
ENRICHMENT_CONFIG = {
    'enabled': os.getenv('ENRICHMENT_ENABLED', 'true').lower() == 'true',
    'providers': {
        'virustotal': {
            'enabled': os.getenv('VIRUSTOTAL_ENABLED', 'false').lower() == 'true',
            'api_key': os.getenv('VIRUSTOTAL_API_KEY', '')
        },
        'abuseipdb': {
            'enabled': os.getenv('ABUSEIPDB_ENABLED', 'false').lower() == 'true',
            'api_key': os.getenv('ABUSEIPDB_API_KEY', '')
        },
        'greynoise': {
            'enabled': os.getenv('GREYNOISE_ENABLED', 'false').lower() == 'true',
            'api_key': os.getenv('GREYNOISE_API_KEY', '')
        }
    },
    'cache_duration': int(os.getenv('CACHE_DURATION', '3600'))
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': os.getenv('LOG_LEVEL', 'INFO'),
    'file': {
        'enabled': os.getenv('LOG_FILE_ENABLED', 'true').lower() == 'true',
        'path': os.getenv('LOG_FILE_PATH', 'logs/tpot2misp.log'),
        'max_size': int(os.getenv('LOG_FILE_MAX_SIZE', '10485760')),
        'backup_count': int(os.getenv('LOG_FILE_BACKUP_COUNT', '5'))
    }
}

# Metrics Configuration
METRICS_CONFIG = {
    'enabled': os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true',
    'port': int(os.getenv('PROMETHEUS_PORT', '9431')),
    'path': os.getenv('PROMETHEUS_METRICS_PATH', '/metrics')
}

# HPFEEDS Configuration
HPFEEDS_CONFIG = {
    'host': os.getenv('HPFEEDS_HOST', 'localhost'),
    'port': int(os.getenv('HPFEEDS_PORT', '10000')),
    'ident': os.getenv('HPFEEDS_IDENT', 'tpot'),
    'secret': os.getenv('HPFEEDS_SECRET', 'secret'),
    'channels': os.getenv('HPFEEDS_CHANNELS', 'tpot.events').split(','),
    'use_tls': os.getenv('HPFEEDS_USE_TLS', 'false').lower() == 'true',
    'tls_cert': os.getenv('HPFEEDS_TLS_CERT', ''),
    'tls_key': os.getenv('HPFEEDS_TLS_KEY', '')
}

# Honeypot type mappings for log parsing
HONEYPOT_MAPPINGS = {
    'cowrie': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'ssh': 'brute-force',
            'telnet': 'brute-force',
            'download': 'malware-download',
            'default': 'reconnaissance'
        }
    },
    'dionaea': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'mssqld': 'sql-injection',
            'smbd': 'smb-exploit',
            'default': 'network-scan'
        }
    },
    # Novos honeypots adicionados com a mesma estrutura simples
    'adbhoney': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'mobile-malware'
        }
    },
    'ciscoasa': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'network-scan'
        }
    },
    'citrixhoneypot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'web-application-attack'
        }
    },
    'conpot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'ics-attack'
        }
    },
    'dicompot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'medical-protocol-attack'
        }
    },
    'elasticpot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'database-scan'
        }
    },
    'glutton': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'network-scan'
        }
    },
    'heralding': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'credential-attack'
        }
    },
    'honeypy': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'network-scan'
        }
    },
    'honeysap': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'erp-attack'
        }
    },
    'honeytrap': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'network-attack'
        }
    },
    'ipphoney': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'printer-attack'
        }
    },
    'log4pot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'rce-attempt'
        }
    },
    'mailoney': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'mail-attack'
        }
    },
    'medpot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'medical-protocol-attack'
        }
    },
    'rdpy': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'rdp-attack'
        }
    },
    'snare': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'web-application-attack'
        }
    },
    'tanner': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'web-application-attack'
        }
    },
    'wordpot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'wordpress-attack'
        }
    },
    'ddospot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'ddos-attack'
        }
    },
    'endlessh': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'ssh-attack'
        }
    },
    'hellpot': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'aggressive-attack'
        }
    },
    'suricata': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'network-scan'
        }
    },
    'p0f': {
        'log_pattern': '**/*.json',
        'attack_types': {
            'default': 'network-fingerprinting'
        }
    }
}

# Valid honeypot types
VALID_HONEYPOTS = {
    'cowrie', 'dionaea', 'adbhoney', 'ciscoasa', 'citrixhoneypot', 'conpot', 'dicompot', 
    'elasticpot', 'glutton', 'heralding', 'honeypy', 'honeysap', 'honeytrap', 'ipphoney',
    'log4pot', 'mailoney', 'medpot', 'rdpy', 'snare', 'tanner', 'wordpot', 'ddospot',
    'endlessh', 'hellpot', 'suricata', 'p0f'
}

# Validation
if not MISP_CONFIG['url']:
    raise ValueError("MISP URL não configurada. Configure a variável MISP_URL")

if not MISP_CONFIG['key']:
    raise ValueError("MISP API key não configurada. Configure a variável MISP_KEY")

if COLLECTION_CONFIG['mode'] not in ['batch', 'realtime']:
    raise ValueError("Modo de coleta inválido. Use 'batch' ou 'realtime'")

if COLLECTION_CONFIG['mode'] == 'realtime' and not HPFEEDS_CONFIG['secret']:
    raise ValueError("HPFEEDS secret não configurado para modo realtime")

if not HPFEEDS_CONFIG['secret']:
    raise ValueError("HPFEEDS secret not configured. Set HPFEEDS_SECRET environment variable.")
