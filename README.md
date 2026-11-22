# NewsInside_Portal — Portal Cativo Omada + LivePix (PIX)

Portal cativo (captive portal) para redes **Omada SDN / TP-Link** com pagamento via **PIX (LivePix)** e conformidade **LGPD**.

## O que faz
Tudo criado via Hermes Agent

## O que faz

1. Cliente conecta ao SSID do portal → EAP intercepta → redireciona para este portal com parâmetros Omada (`clientMac`, `clientIp`, `apMac`, `ssidName`, `radioId`, `t`)
2. Usuário faz cadastro (validação de identidade LGPD) ou login
3. Geração de cobrança PIX via **LivePix** (R$ 5,00 padrão; R$ 25,00 para Apple)
4. Após confirmação do pagamento, autorização via **Omada External Portal auth** (`authType 4` — 1 hora, rate limit configurável)
5. Sessão expira automaticamente; varredura de expiração desautoriza no Omada

## LGPD (Lei 13.709/2018)

- Consentimento explícito no cadastro e login
- CPF armazenado **apenas como hash SHA-256** (nunca em claro)
- Nome de registro **não é lido nem exposto** quando o usuário declara nome social
- Direitos do titular: exportação (`/me/export`) e exclusão total (`/me/delete`)
- Retenção configurável (padrão: 90 dias); logs por usuário em texto legível + JSON
- Validação opcional via **Cadastro Base do Cidadão (CBC — gov.br/Serpro)**

## Estrutura do projeto

```
portal/
├── portal_server.py          # Servidor Flask-like (stdlib only)
├── .env.example              # Exemplo de variáveis de ambiente (copie para .env)
├── .gitignore                # Ignora secrets, banco, logs e __pycache__
├── README.md                 # Este arquivo
├── portal.service            # Unit do systemd para execução como serviço
├── test_lgpd_validacao.py    # Testes automatizados de validação LGPD
├── data/                     # Banco SQLite + config (não versionar)
├── logs/                     # Logs do portal e de usuários (não versionar)
├── static/
│   └── omada-portal.crt      # Certificado da rede para clientes
└── templates/
    ├── login.html            # Página de login e cadastro
    ├── pay.html              # Página de pagamento PIX
    └── privacy.html          # Política de privacidade (LGPD)
```

## Instalação rápida

```bash
# 1. Clone o repositório
git clone https://github.com/Amiell3/omada-portal.git
cd omada-portal

# 2. Copie o exemplo de ambiente e edite
cp .env.example .env
nano .env   # preencha com seus valores (LivePix, Omada, CBC, etc.)

# 3. Carregue as variáveis
source .env   # ou defina no ambiente do seu SO/Docker

# 4. Execute
python3 portal_server.py

# Acesse: http://localhost:8089
```

## Variáveis de ambiente (.env)

| Variável | Descrição | Exemplo |
|----------|-----------|---------|
| `PORTAL_PORT` | Porta de escuta | `8089` |
| `CONTROLLER_BASE` | URL do controller Omada | `https://localhost:8043` |
| `OMADAC_ID` | ID do controller Omada | `343a2330...` |
| `SITE_ID` | ID do site Omada | `69e15e04...` |
| `PORTAL_PUBLIC_BASE` | URL pública vista pelos clientes | `http://192.168.0.3:8089` |
| `PRICE_BRL_CENTS` | Preço PIX em centavos | `500` (R$ 5,00) |
| `PRICE_APPLE_BRL_CENTS` | Preço Apple em centavos | `2500` (R$ 25,00) |
| `RATE_LIMIT_KBPS` | Limite taxa padrão (kbps) | `250000` |
| `APPLE_RATE_LIMIT_KBPS` | Limite taxa Apple (kbps) | `100000` |
| `SESSION_DURATION_MIN` | Duração sessão (min) | `60` |
| `RETENTION_DAYS` | Retenção logs (dias) | `90` |
| `LIVEPIX_CLIENT_ID` | Client ID LivePix | `...` |
| `LIVEPIX_CLIENT_SECRET` | Client Secret LivePix | `...` |
| `HOTSPOT_OPERATOR` | Usuário hotspot Omada | `portalop` |
| `HOTSPOT_PASSWORD` | Senha hotspot Omada | `...` |
| `PORTAL_TEST_USERS` | Usuários teste (simulação PIX) | `Amielle` |
| `CBC_ENV` | `off` \| `homolog` \| `prod` | `off` |
| `CBC_CLIENT_ID` | Client ID CBC/Serpro | `...` |
| `CBC_CLIENT_SECRET` | Client Secret CBC/Serpro | `...` |
| `CBC_X_CPF_USUARIO` | CPF responsável (header) | `...` |
| `CBC_REQUIRED` | Bloquear se CBC fora do ar | `false` |

## API do portal

| Método | Caminho | Descrição |
|--------|---------|-----------|
| GET | `/` ou `/login` | Página de login/cadastro |
| GET | `/pay?t=TOKEN` | Página de pagamento PIX |
| POST | `/pay/create` | Gera cobrança PIX |
| POST | `/pay/simulate` | Simula pagamento (usuários teste) |
| GET | `/check?t=TOKEN` | Verifica status do pagamento/sessão |
| GET | `/status?t=TOKEN` | Status autorizado/expira |
| GET | `/privacy` | Política de privacidade |
| GET | `/me/export?t=TOKEN` | Exporta dados do titular (LGPD) |
| GET | `/me/delete?t=TOKEN` | Exclui todos os dados do titular (LGPD) |
| GET | `/cert/omada-portal.crt` | Download do certificado da rede |

## Executar como serviço (systemd)

Copie `portal.service` para `/etc/systemd/system/`, edite os caminhos e:

```bash
sudo cp portal.service /etc/systemd/system/omada-portal.service
sudo systemctl daemon-reload
sudo systemctl enable --now omada-portal
```

## Testes LGPD

```bash
python3 test_lgpd_validacao.py
```

## Requisitos

- Python 3.10+
- Acesso ao controller Omada (API local)
- Conta LivePix com credenciais de API
- (Opcional) Contrato CBC/Serpro para validação de CPF oficial

## Licença

Uso interno / educacional. Dados sensíveis (secrets, banco, logs) **nunca** devem ser versionados.
