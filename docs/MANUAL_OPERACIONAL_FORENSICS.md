# 🔬 Manual Operacional - Módulo Forensics & Investigation

<div align="center">

**NAZARIUS SIEM**  
*Security Information and Event Management*

---

**DOCUMENTO OPERACIONAL**  
**Módulo: Forensics & Investigation**

**Versão:** 1.0  
**Data:** Janeiro 2025  
**Classificação:** Interno - Equipe de Segurança

---

</div>

## Sumário

1. [Introdução](#1-introdução)
2. [Acesso ao Módulo](#2-acesso-ao-módulo)
3. [Interface do Usuário](#3-interface-do-usuário)
4. [Gestão de Investigações](#4-gestão-de-investigações)
5. [Gestão de Evidências](#5-gestão-de-evidências)
6. [Timeline de Eventos](#6-timeline-de-eventos)
7. [Fluxos Operacionais](#7-fluxos-operacionais)
8. [Boas Práticas](#8-boas-práticas)
9. [Troubleshooting](#9-troubleshooting)
10. [Glossário](#10-glossário)

---

## 1. Introdução

### 1.1 Objetivo

O módulo **Forensics & Investigation** é uma ferramenta especializada para condução de investigações forenses digitais, permitindo a coleta, análise e documentação de evidências de incidentes de segurança.

### 1.2 Escopo

Este módulo permite:

- ✅ Criar e gerenciar investigações forenses
- ✅ Coletar e catalogar evidências digitais
- ✅ Manter cadeia de custódia de evidências
- ✅ Documentar timeline de eventos
- ✅ Gerar relatórios de investigação
- ✅ Integrar com alertas e casos do SIEM

### 1.3 Público-Alvo

| Perfil | Responsabilidades |
|--------|-------------------|
| **Analista SOC** | Criar investigações, coletar evidências iniciais |
| **Analista Forense** | Conduzir análises detalhadas, documentar findings |
| **Incident Responder** | Coordenar investigações, documentar timeline |
| **SOC Manager** | Supervisionar investigações, revisar conclusões |

### 1.4 Pré-requisitos

- Acesso autenticado ao NAZARIUS SIEM
- Permissões de acesso ao módulo Forensics
- Conhecimento básico em análise forense digital

---

## 2. Acesso ao Módulo

### 2.1 Navegação

1. Faça login no NAZARIUS SIEM
2. No menu lateral, localize a seção **"Detecção & Resposta"**
3. Clique em **"Forensics"**

```
Menu Principal
├── Dashboard
├── Detecção & Resposta
│   ├── Eventos
│   ├── Alertas
│   ├── Casos
│   ├── Forensics  ◄── Clique aqui
│   ├── Incident Response
│   └── Playbooks (SOAR)
└── ...
```

### 2.2 URL Direta

```
https://[seu-dominio]/forensics
```

---

## 3. Interface do Usuário

### 3.1 Visão Geral da Tela

```
┌────────────────────────────────────────────────────────────────────────────┐
│  FORENSICS & INVESTIGATION                    [🟢 LIVE DATA] [↻] [+ Nova] │
├────────────────────────────────────────────────────────────────────────────┤
│  ℹ️ Módulo Forensics: Análise forense digital com persistência em          │
│     OpenSearch. Coleta de evidências, timeline de eventos...               │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │    Total     │  │    Ativas    │  │  Evidências  │  │  Artefatos   │   │
│  │ Investigações│  │              │  │  Coletadas   │  │  Analisados  │   │
│  │      12      │  │      3       │  │     847      │  │    1523      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │ [Investigações]  [Evidências]                                        │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │ 🔍 Buscar...     │ Status ▼ │ Severidade ▼ │        [Filtrar]       │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │ TÍTULO            │STATUS│SEVERID│EVID│ANALISTA    │DATA   │AÇÕES  │  │
│  ├───────────────────┼──────┼───────┼────┼────────────┼───────┼───────┤  │
│  │ Ransomware Attack │active│critical│ 45 │john.doe   │06/01  │👁📦⏱🗑│  │
│  │ Data Exfiltration │active│ high  │ 32 │jane.smith │05/01  │👁📦⏱🗑│  │
│  │ Insider Threat    │pending│medium│ 28 │soc.lead   │04/01  │👁📦⏱🗑│  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Componentes da Interface

| Componente | Descrição |
|------------|-----------|
| **Indicador de Dados** | Mostra se os dados são reais (LIVE) ou demonstração (DEMO) |
| **Botão Atualizar** | Recarrega os dados da tela |
| **Botão Nova Investigação** | Abre formulário para criar investigação |
| **Cards de Estatísticas** | Resumo numérico das investigações |
| **Abas** | Alterna entre Investigações e Evidências |
| **Filtros** | Permite filtrar por busca, status e severidade |
| **Tabela** | Lista de investigações ou evidências |

### 3.3 Indicadores de Status

| Indicador | Significado |
|-----------|-------------|
| 🟢 **LIVE DATA** | Dados reais persistidos no OpenSearch |
| 🔴 **DEMO DATA** | Dados de demonstração (não persistidos) |
| 🟡 **NO DATA** | Sem conexão com OpenSearch |

### 3.4 Ícones de Ação

| Ícone | Ação | Descrição |
|-------|------|-----------|
| 👁️ | Ver Detalhes | Abre painel com informações completas |
| 📦 | Adicionar Evidência | Abre formulário para nova evidência |
| ⏱️ | Adicionar Evento | Abre formulário para evento na timeline |
| 🗑️ | Excluir | Remove a investigação (requer confirmação) |

---

## 4. Gestão de Investigações

### 4.1 Criar Nova Investigação

**Passo a passo:**

1. Clique no botão **"+ Nova Investigação"** no canto superior direito
2. Preencha o formulário conforme a tabela abaixo
3. Clique em **"Criar Investigação"**

**Campos do Formulário:**

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| **Título** | Texto | ✅ Sim | Nome descritivo da investigação |
| **Descrição** | Texto longo | Não | Detalhes sobre o incidente investigado |
| **Severidade** | Seleção | Sim | Nível de criticidade |
| **Prioridade** | Seleção | Sim | Prioridade de atendimento |
| **ID do Incidente** | Texto | Não | Referência ao incidente no sistema |
| **ID do Caso** | Texto | Não | Referência ao caso relacionado |
| **Tags** | Texto | Não | Palavras-chave separadas por vírgula |
| **Notas** | Texto longo | Não | Observações adicionais |

**Níveis de Severidade:**

| Severidade | Cor | Critérios |
|------------|-----|-----------|
| **Critical** | 🔴 Vermelho | Impacto severo em sistemas críticos, dados sensíveis comprometidos |
| **High** | 🟠 Laranja | Impacto significativo, requer ação urgente |
| **Medium** | 🟡 Amarelo | Impacto moderado, requer investigação |
| **Low** | 🟢 Verde | Impacto mínimo, investigação de rotina |

**Exemplo de Preenchimento:**

```
Título:       Ransomware Incident - Production Database Server
Descrição:    Investigação de incidente de ransomware detectado no servidor 
              de banco de dados de produção. Arquivos criptografados 
              identificados às 14:30 do dia 06/01/2025.
Severidade:   Critical
Prioridade:   Critical
ID Incidente: INC-2025-0042
ID Caso:      CASE-2025-0015
Tags:         ransomware, lockbit, production, database, pci-dss
Notas:        Servidor isolado da rede às 14:45. Backup mais recente: 06:00.
```

### 4.2 Visualizar Investigação

1. Localize a investigação na tabela
2. Clique no ícone **👁️ (Ver Detalhes)**
3. O painel de detalhes exibirá:
   - Informações gerais
   - Tags associadas
   - Timeline de eventos
   - Opções para adicionar eventos

### 4.3 Status de Investigação

| Status | Descrição | Uso |
|--------|-----------|-----|
| **Active** | Em andamento | Investigação sendo conduzida ativamente |
| **Pending** | Aguardando | Aguardando informações ou recursos |
| **Completed** | Concluída | Investigação finalizada com conclusões |
| **Archived** | Arquivada | Investigação arquivada para referência |

### 4.4 Filtrar Investigações

**Por Busca Textual:**
- Digite no campo de busca
- Busca em: título, descrição, analista
- Pressione Enter ou clique em "Filtrar"

**Por Status:**
- Selecione no dropdown "Status"
- Opções: Todos, Ativo, Concluído, Pendente, Arquivado

**Por Severidade:**
- Selecione no dropdown "Severidade"
- Opções: Todas, Crítica, Alta, Média, Baixa

### 4.5 Excluir Investigação

⚠️ **ATENÇÃO: Esta ação é irreversível!**

1. Clique no ícone **🗑️ (Excluir)**
2. Confirme no diálogo de confirmação
3. A investigação e todos os dados associados serão removidos

---

## 5. Gestão de Evidências

### 5.1 Tipos de Evidência

| Tipo | Código | Descrição | Exemplos |
|------|--------|-----------|----------|
| **Arquivo** | `file` | Arquivos suspeitos ou maliciosos | `.exe`, `.dll`, `.doc`, `.pdf` |
| **Memória** | `memory` | Dumps de memória de processos ou sistema | `.dmp`, `.mem`, `.raw` |
| **Rede** | `network` | Capturas de tráfego de rede | `.pcap`, `.pcapng` |
| **Log** | `log` | Logs de sistema ou aplicação | `.evtx`, `.log`, `.json` |
| **Registry** | `registry` | Exportações de registro Windows | `.reg`, hives |
| **Disco** | `disk` | Imagens forenses de disco | `.E01`, `.dd`, `.raw` |
| **Processo** | `process` | Dumps de processos específicos | `.dmp` |

### 5.2 Adicionar Evidência

1. Na linha da investigação, clique no ícone **📦**
2. Preencha o formulário:

| Campo | Descrição | Exemplo |
|-------|-----------|---------|
| **Tipo** | Categoria da evidência | `file` |
| **Nome** | Identificador único | `malware_sample.exe` |
| **Origem** | Caminho ou fonte original | `C:\Windows\Temp\update.exe` |
| **Hash (SHA-256)** | Hash para verificação de integridade | `e3b0c44298fc1c149afbf4...` |
| **Tamanho** | Tamanho em bytes | `1048576` |
| **Tags** | Palavras-chave | `suspicious, pe-file, packed` |

3. Clique em **"Adicionar"**

### 5.3 Cadeia de Custódia

O sistema mantém automaticamente o registro de cadeia de custódia:

```
┌─────────────────────────────────────────────────────────────┐
│ CADEIA DE CUSTÓDIA - Evidência: malware_sample.exe         │
├─────────────────────────────────────────────────────────────┤
│ 2025-01-06 14:45:00 │ COLLECTED  │ john.doe@company.com    │
│                     │            │ Coletado do endpoint    │
│                     │            │ WORKSTATION-015         │
├─────────────────────────────────────────────────────────────┤
│ 2025-01-06 15:30:00 │ ANALYZED   │ malware.analyst@co.com  │
│                     │            │ Submetido ao sandbox    │
├─────────────────────────────────────────────────────────────┤
│ 2025-01-06 16:00:00 │ CLASSIFIED │ malware.analyst@co.com  │
│                     │            │ Classificado como       │
│                     │            │ ransomware LockBit 3.0  │
└─────────────────────────────────────────────────────────────┘
```

### 5.4 Visualizar Evidências

1. Clique na aba **"Evidências"**
2. A tabela exibe todas as evidências coletadas
3. Informações disponíveis:
   - Nome e tipo
   - Origem
   - Hash (truncado)
   - Tamanho
   - Status
   - Data de coleta

### 5.5 Calcular Hash SHA-256

**Windows (PowerShell):**
```powershell
Get-FileHash -Algorithm SHA256 -Path "C:\caminho\arquivo.exe"
```

**Linux/macOS:**
```bash
sha256sum /caminho/arquivo.exe
```

---

## 6. Timeline de Eventos

### 6.1 Conceito

A timeline documenta cronologicamente todos os eventos relevantes da investigação, permitindo reconstruir a sequência de ações do incidente.

### 6.2 Tipos de Evento

| Tipo | Código | Descrição |
|------|--------|-----------|
| **Sistema** | `system` | Eventos do sistema de investigação |
| **Evidência** | `evidence` | Coleta ou análise de evidências |
| **Descoberta** | `finding` | Achados da investigação |
| **Análise** | `analysis` | Resultados de análises |
| **Rede** | `network` | Eventos relacionados à rede |
| **Usuário** | `user` | Ações de usuários |
| **Arquivo** | `file` | Operações em arquivos |
| **Processo** | `process` | Eventos de processos |

### 6.3 Adicionar Evento à Timeline

1. Clique no ícone **⏱️** na investigação OU
2. Dentro dos detalhes, clique em **"Adicionar Evento"**
3. Preencha:

| Campo | Descrição | Exemplo |
|-------|-----------|---------|
| **Evento** | Descrição do que ocorreu | `Lateral movement detected` |
| **Tipo** | Categoria do evento | `finding` |
| **Alvo** | Sistema/recurso afetado | `SERVER-01` |
| **Detalhes** | Informações adicionais | `RDP from WORKSTATION to SERVER` |
| **Severidade** | Importância do evento | `critical` |

4. Clique em **"Adicionar"**

### 6.4 Exemplo de Timeline Completa

```
TIMELINE - Investigação: Ransomware Incident

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📅 06/01/2025 09:15:00 │ INFO
   [system] Investigation created
   Por: soc.analyst@company.com
   Detalhes: Investigação iniciada após alerta de EDR

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📅 06/01/2025 09:30:00 │ HIGH
   [finding] Phishing email identified
   Alvo: user@company.com
   Por: soc.analyst@company.com
   Detalhes: Email com anexo malicioso recebido às 08:45

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📅 06/01/2025 10:00:00 │ CRITICAL
   [finding] Malware execution detected
   Alvo: WORKSTATION-015
   Por: edr.system
   Detalhes: Processo suspeito update.exe iniciado às 08:47

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📅 06/01/2025 10:30:00 │ HIGH
   [evidence] Malware sample collected
   Alvo: WORKSTATION-015
   Por: forensic.analyst@company.com
   Detalhes: C:\Windows\Temp\update.exe coletado
             Hash: e3b0c44298fc1c149afbf4c8996fb924...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📅 06/01/2025 11:00:00 │ CRITICAL
   [analysis] Malware identified
   Por: malware.analyst@company.com
   Detalhes: Identificado como LockBit 3.0 ransomware
             IOCs extraídos e compartilhados com TI

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📅 06/01/2025 12:00:00 │ CRITICAL
   [finding] Lateral movement detected
   Alvo: FILE-SERVER-01
   Por: forensic.analyst@company.com
   Detalhes: RDP de WORKSTATION-015 para FILE-SERVER-01 às 09:30
             Credenciais comprometidas do usuário admin_backup

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📅 06/01/2025 14:00:00 │ INFO
   [system] Containment completed
   Por: incident.responder@company.com
   Detalhes: Sistemas isolados, credenciais resetadas
             Iniciando fase de erradicação

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 7. Fluxos Operacionais

### 7.1 Fluxo Padrão de Investigação

```
┌─────────────────────────────────────────────────────────────────┐
│                    FLUXO DE INVESTIGAÇÃO                        │
└─────────────────────────────────────────────────────────────────┘

    ┌──────────────┐
    │   TRIGGER    │  ← Alerta, Caso ou Solicitação
    │   (Início)   │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │    CRIAR     │  ← Nova Investigação no sistema
    │ INVESTIGAÇÃO │     Definir severidade e prioridade
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │   COLETAR    │  ← Arquivos, logs, dumps de memória
    │  EVIDÊNCIAS  │     Manter cadeia de custódia
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │   ANALISAR   │  ← Sandbox, análise estática/dinâmica
    │  ARTEFATOS   │     Correlação com IOCs conhecidos
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  DOCUMENTAR  │  ← Registrar na timeline
    │   FINDINGS   │     Mapear MITRE ATT&CK
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │   CONCLUIR   │  ← Relatório final
    │ INVESTIGAÇÃO │     Recomendações
    └──────────────┘
```

### 7.2 Fluxo de Resposta a Ransomware

```
HORA 0 (Detecção)
├── Criar investigação com severidade CRITICAL
├── Registrar na timeline: "Ransomware detected"
└── Isolar sistemas afetados

HORA 1-2 (Contenção)
├── Coletar evidências dos sistemas isolados
│   ├── Memory dump
│   ├── Malware samples
│   └── Event logs
├── Documentar sistemas afetados na timeline
└── Identificar vetor de entrada

HORA 2-4 (Análise)
├── Analisar malware em sandbox
├── Extrair IOCs (hashes, IPs, domínios)
├── Identificar variante de ransomware
└── Documentar findings na timeline

HORA 4-8 (Erradicação)
├── Remover malware dos sistemas
├── Resetar credenciais comprometidas
├── Bloquear IOCs no perímetro
└── Documentar ações na timeline

HORA 8+ (Recuperação)
├── Restaurar sistemas de backup
├── Validar integridade
├── Monitorar por reinfecção
└── Concluir investigação
```

### 7.3 Checklist de Investigação

```
□ Investigação criada com título descritivo
□ Severidade e prioridade definidas corretamente
□ ID do incidente vinculado (se aplicável)
□ Tags relevantes adicionadas

□ Evidências coletadas:
  □ Malware/arquivos suspeitos
  □ Logs de sistema
  □ Logs de aplicação
  □ Dumps de memória (se necessário)
  □ Capturas de rede (se aplicável)

□ Cadeia de custódia mantida:
  □ Hashes calculados para todas as evidências
  □ Origem documentada
  □ Coleta registrada na timeline

□ Timeline documentada:
  □ Vetor de entrada identificado
  □ Ações do atacante mapeadas
  □ Sistemas afetados listados
  □ Ações de resposta registradas

□ Conclusão:
  □ Root cause identificado
  □ MITRE ATT&CK mapeado
  □ Recomendações documentadas
  □ Status atualizado para "Completed"
```

---

## 8. Boas Práticas

### 8.1 Nomenclatura

**Títulos de Investigação:**
```
✅ Bom:  "Ransomware Incident - Production File Server - Jan 2025"
✅ Bom:  "Data Exfiltration - Customer Database - INC-2025-0042"
❌ Ruim: "Investigação 1"
❌ Ruim: "Problema no servidor"
```

**Tags:**
```
✅ Usar tags padronizadas:
   - Tipo de ataque: ransomware, phishing, data-breach, insider-threat
   - Sistemas: production, development, dmz, cloud
   - Compliance: pci-dss, lgpd, sox, hipaa
   - Prioridade: critical, urgent
```

### 8.2 Documentação

| Sempre Documentar | Nunca Fazer |
|-------------------|-------------|
| ✅ Todos os passos da análise | ❌ Alterar evidências originais |
| ✅ Horários precisos (UTC) | ❌ Executar malware em produção |
| ✅ Quem realizou cada ação | ❌ Omitir passos da investigação |
| ✅ Ferramentas utilizadas | ❌ Apagar logs durante análise |
| ✅ Hash de todas as evidências | ❌ Trabalhar sem backup |

### 8.3 Cadeia de Custódia

Para garantir validade legal das evidências:

1. **Calcule o hash** imediatamente após coleta
2. **Documente a origem** com precisão
3. **Registre quem coletou** e quando
4. **Não modifique** a evidência original
5. **Trabalhe em cópias** para análise

### 8.4 Timeline

**Estrutura recomendada para eventos:**

```
[TIPO_EVENTO] Descrição clara e objetiva

Exemplo:
[finding] Malware execution detected on WORKSTATION-015

Detalhes:
- Processo: update.exe (PID 4532)
- Usuário: john.doe
- Horário: 2025-01-06 08:47:32 UTC
- Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

## 9. Troubleshooting

### 9.1 Problemas Comuns

| Problema | Causa | Solução |
|----------|-------|---------|
| Dados não carregam | Conexão com API | Verificar conectividade, recarregar página |
| "DEMO DATA" exibido | OpenSearch indisponível | Contatar administrador do sistema |
| Erro ao criar investigação | Campos obrigatórios vazios | Verificar preenchimento do título |
| Evidência não adicionada | Hash inválido | Verificar formato SHA-256 (64 caracteres hex) |
| Timeline vazia | Investigação nova | Adicionar eventos manualmente |

### 9.2 Mensagens de Erro

| Mensagem | Significado | Ação |
|----------|-------------|------|
| "Erro ao carregar dados" | Falha na API | Tentar novamente, verificar conexão |
| "Erro ao criar investigação" | Falha no backend | Verificar campos, tentar novamente |
| "Investigation not found" | ID inválido | Verificar se investigação existe |
| "Failed to create evidence" | Erro de validação | Verificar todos os campos |

### 9.3 Suporte

Para problemas não resolvidos:

1. **Nível 1:** Recarregar página, limpar cache
2. **Nível 2:** Contatar equipe de suporte SIEM
3. **Nível 3:** Abrir chamado para equipe de desenvolvimento

---

## 10. Glossário

| Termo | Definição |
|-------|-----------|
| **Artefato** | Objeto digital relevante para a investigação |
| **Cadeia de Custódia** | Documentação do histórico de manipulação de evidências |
| **EDR** | Endpoint Detection and Response |
| **Finding** | Descoberta relevante durante a investigação |
| **Hash** | Valor único calculado a partir do conteúdo de um arquivo |
| **IOC** | Indicator of Compromise - indicador de comprometimento |
| **MITRE ATT&CK** | Framework de táticas e técnicas de adversários |
| **PCAP** | Packet Capture - captura de pacotes de rede |
| **Sandbox** | Ambiente isolado para análise de malware |
| **SHA-256** | Algoritmo de hash criptográfico |
| **SOC** | Security Operations Center |
| **Timeline** | Linha do tempo de eventos |
| **Triage** | Processo de priorização e classificação inicial |

---

## Controle de Versões

| Versão | Data | Autor | Alterações |
|--------|------|-------|------------|
| 1.0 | Jan 2025 | Security Team | Versão inicial |

---

<div align="center">

**NAZARIUS SIEM**  
*Protegendo sua infraestrutura digital*

---

*Este documento é de uso interno e contém informações confidenciais.*  
*Não compartilhe fora da organização sem autorização.*

</div>

