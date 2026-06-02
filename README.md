# SecuraPy — SIEM Simplificado 

Disciplina: Coding for Security  
Tipo: Trabalho Final Prático  
Peso: 40% da nota final

---

Descrição do Projeto

O **SecuraPy** é um SIEM (Security Information and Event Management) simplificado desenvolvido em Python. O sistema coleta, analisa e correlaciona eventos de segurança de múltiplas fontes de log em tempo real, detectando ataques como brute force, port scan e tentativas de invasão web.

---

Integrantes e Divisão de Tarefas

| Integrante | Módulos Responsável |
|------------|---------------------|
| Pessoa A   | `coletor.py` + arquivos de log de teste |
| Pessoa B   | `regras.py` + `detector.py` + `config/regras.json` |
| Pessoa C   | `servidor_alertas.py` + `cliente_alertas.py` |
| Pessoa D   | `enriquecimento.py` + `relatorios.py` + `main.py` |

---

Estrutura do Projeto

```
securaPy/
├── main.py                 # Ponto de entrada e menu principal
├── coletor.py              # Módulo 1 — Leitura e parsing de logs
├── regras.py               # Módulo 2 — Motor de regras de detecção
├── detector.py             # Módulo 3 — Detecção de anomalias e ataques
├── servidor_alertas.py     # Módulo 4 — Servidor TCP de alertas
├── cliente_alertas.py      # Módulo 4 — Cliente TCP de alertas
├── enriquecimento.py       # Módulo 5 — Consulta a APIs de threat intelligence
├── relatorios.py           # Módulo 6 — Dashboard CLI e relatórios
├── logs/
│   ├── auth.log
│   ├── firewall.log
│   └── web_access.log
├── config/
│   └── regras.json
├── saida/
│   └── (relatórios gerados)
└── README.md
```

---

Como Executar:

Pré-requisitos

- Python 3.8 ou superior
- Instalar dependência:

```bash
pip install requests
```

Executar o sistema principal

```bash
cd securaPy
python main.py
```

Executar o servidor de alertas separadamente

```bash
# Terminal 1 — Servidor
python servidor_alertas.py

# Terminal 2 — Cliente 1
python cliente_alertas.py

# Terminal 3 — Cliente 2 (opcional)
python cliente_alertas.py
```

Testar módulos individualmente

```bash
python coletor.py
python regras.py
python detector.py
python enriquecimento.py
```

---

Dados de Teste

Os arquivos na pasta `logs/` contêm eventos simulados que ativam todas as detecções:

| Arquivo | Eventos | Ataques simulados |
|---------|---------|-------------------|
| `auth.log` | 23 linhas | Brute force em admin/root de IPs externos |
| `firewall.log` | 17 linhas | Port scan varrendo portas críticas |
| `web_access.log` | 18 linhas | Path traversal, XSS, reconhecimento web |

### IPs suspeitos nos logs

| IP | Tipo de ameaça |
|----|----------------|
| `185.220.101.1` | Brute force + Port scan + Blacklist |
| `91.240.118.172` | Brute force + Port scan + Blacklist |
| `45.33.32.156` | Port scan + Blacklist |

---

Funcionalidades

1. **Carregar e processar logs** — lê as 3 fontes e normaliza eventos
2. **Resumo geral** — visão consolidada com contadores
3. **Filtrar eventos** — por fonte, tipo e IP
4. **Buscar IP** — histórico completo de um IP específico
5. **Top 10 IPs** — ranking dos IPs mais ativos com indicador de ameaça
6. **Alertas por severidade** — CRITICA / ALTA / MEDIA / BAIXA / INFO
7. **Enriquecimento** — geolocalização dos IPs via ipinfo.io
8. **Exportar relatório** — JSON com todos os dados da análise
9. **Servidor de alertas** — broadcast TCP em tempo real

---

Referências

- [ipinfo.io API](https://ipinfo.io) — geolocalização de IPs
- Python docs: `socket`, `threading`, `json`, `os`, `requests`
