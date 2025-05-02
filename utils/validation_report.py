import json
import os
from datetime import datetime
from typing import Dict, List, Any

class ValidationReportGenerator:
    def __init__(self, config: Dict[str, Any]):
        """
        Inicializa o gerador de relatórios de validação.
        
        Args:
            config: Configurações do sistema
        """
        self.report_dir = config.get('VALIDATION_REPORT_DIR', 'reports')
        self.report_format = config.get('VALIDATION_REPORT_FORMAT', 'txt').lower()
        
        # Criar diretório de relatórios se não existir
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
        
        # Inicializar contadores
        self.honeypot_events = {}
        self.total_attributes = 0
        self.misp_events_created = []
        self.misp_events_updated = []

    def add_attribute(self, honeypot_type: str, attribute_type: str, value: str):
        """
        Registra um atributo adicionado ao MISP.
        
        Args:
            honeypot_type: Tipo de honeypot (ex: cowrie, dionaea)
            attribute_type: Tipo de atributo MISP (ex: ip-src, url)
            value: Valor do atributo
        """
        if honeypot_type not in self.honeypot_events:
            self.honeypot_events[honeypot_type] = {
                'attributes': {},
                'total': 0
            }
            
        if attribute_type not in self.honeypot_events[honeypot_type]['attributes']:
            self.honeypot_events[honeypot_type]['attributes'][attribute_type] = []
            
        self.honeypot_events[honeypot_type]['attributes'][attribute_type].append(value)
        self.honeypot_events[honeypot_type]['total'] += 1
        self.total_attributes += 1

    def register_misp_event(self, event_id: str, honeypot_type: str, is_new: bool = True):
        """
        Registra um evento MISP criado ou atualizado.
        
        Args:
            event_id: ID do evento MISP
            honeypot_type: Tipo de honeypot
            is_new: True se o evento foi criado, False se foi atualizado
        """
        event_data = {
            'id': event_id,
            'honeypot_type': honeypot_type,
            'timestamp': datetime.now().isoformat()
        }
        
        if is_new:
            self.misp_events_created.append(event_data)
        else:
            self.misp_events_updated.append(event_data)

    def generate_report(self) -> str:
        """
        Gera um relatório de validação.
        
        Returns:
            Caminho para o arquivo de relatório gerado
        """
        now = datetime.now()
        filename = f"validation_report_{now.strftime('%Y%m%d_%H%M%S')}.{self.report_format}"
        filepath = os.path.join(self.report_dir, filename)
        
        if self.report_format == 'json':
            return self._generate_json_report(filepath)
        else:
            return self._generate_txt_report(filepath)

    def _generate_txt_report(self, filepath: str) -> str:
        """
        Gera um relatório em formato de texto.
        """
        with open(filepath, 'w') as f:
            f.write("T-POT TO MISP VALIDATION REPORT\n")
            f.write("=" * 40 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("SUMÁRIO\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total de atributos adicionados: {self.total_attributes}\n")
            f.write(f"Total de eventos MISP criados: {len(self.misp_events_created)}\n")
            f.write(f"Total de eventos MISP atualizados: {len(self.misp_events_updated)}\n\n")
            
            f.write("DETALHES POR HONEYPOT\n")
            f.write("-" * 40 + "\n")
            
            for honeypot, data in self.honeypot_events.items():
                f.write(f"\nHoneypot: {honeypot.upper()}\n")
                f.write(f"Total de atributos: {data['total']}\n")
                
                for attr_type, values in data['attributes'].items():
                    f.write(f"\n  {attr_type} ({len(values)} atributos):\n")
                    for value in values:
                        f.write(f"    - {value}\n")
            
            f.write("\nEVENTOS MISP CRIADOS\n")
            f.write("-" * 40 + "\n")
            for event in self.misp_events_created:
                f.write(f"  - Evento ID: {event['id']}, Honeypot: {event['honeypot_type']}\n")
            
            f.write("\nEVENTOS MISP ATUALIZADOS\n")
            f.write("-" * 40 + "\n")
            for event in self.misp_events_updated:
                f.write(f"  - Evento ID: {event['id']}, Honeypot: {event['honeypot_type']}\n")
                
        return filepath

    def _generate_json_report(self, filepath: str) -> str:
        """
        Gera um relatório em formato JSON.
        """
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_attributes': self.total_attributes,
                'events_created': len(self.misp_events_created),
                'events_updated': len(self.misp_events_updated)
            },
            'honeypots': self.honeypot_events,
            'misp_events': {
                'created': self.misp_events_created,
                'updated': self.misp_events_updated
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        return filepath