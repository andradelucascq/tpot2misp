#!/bin/bash
echo "===== tpot2misp Docker Setup ====="

# Criar diretórios necessários
mkdir -p data logs

echo ""
echo "Iniciando o contêiner tpot2misp..."
docker-compose up -d

echo ""
echo "Para visualizar os logs em tempo real, execute:"
echo "docker-compose logs -f"

echo ""
echo "Para parar o contêiner, execute:"
echo "docker-compose down"

echo ""
echo "Instalação concluída! O contêiner está rodando em segundo plano."