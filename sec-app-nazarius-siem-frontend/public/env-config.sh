#!/bin/sh
# Script para gerar configuração de ambiente em runtime
# Isso permite mudar a API_URL sem rebuild da imagem

# Valores padrão
API_URL="${REACT_APP_API_URL:-http://localhost:8080/api/v1}"

# Gera o arquivo JavaScript com as variáveis de ambiente
cat > /usr/share/nginx/html/env-config.js << EOF
window.__ENV__ = {
  REACT_APP_API_URL: "${API_URL}"
};
EOF

echo "✅ Environment configuration generated:"
echo "   API_URL: ${API_URL}"

