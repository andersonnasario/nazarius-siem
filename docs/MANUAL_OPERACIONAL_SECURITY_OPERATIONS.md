# Manual Operacional - Security Operations

## NAZARIUS SIEM & SOC Platform
### Módulos: Eventos, Alertas e Casos

**Versão:** 1.0  
**Data:** Janeiro 2026  
**Classificação:** Uso Interno - Equipe de Operações SOC

---

## Índice

1. [Visão Geral](#1-visão-geral)
2. [Módulo de Eventos](#2-módulo-de-eventos)
3. [Módulo de Alertas](#3-módulo-de-alertas)
4. [Módulo de Casos](#4-módulo-de-casos)
5. [Fluxo Operacional Integrado](#5-fluxo-operacional-integrado)
6. [Boas Práticas](#6-boas-práticas)
7. [Troubleshooting](#7-troubleshooting)
8. [Glossário](#8-glossário)

---

## 1. Visão Geral

### 1.1 Objetivo do Documento

Este manual fornece orientações detalhadas para operacionalização dos módulos de **Eventos**, **Alertas** e **Casos** do NAZARIUS SIEM, permitindo que analistas de segurança executem suas atividades de forma eficiente e padronizada.

### 1.2 Arquitetura dos Módulos

```
┌─────────────────────────────────────────────────────────────────┐
│                        SECURITY OPERATIONS                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│   │   EVENTOS    │───▶│   ALERTAS    │───▶│    CASOS     │      │
│   │  (Detecção)  │    │ (Qualificação)│   │(Investigação)│      │
│   └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                   │               │
│         ▼                    ▼                   ▼               │
│   ┌─────────────────────────────────────────────────────┐       │
│   │               OpenSearch (Persistência)              │       │
│   └─────────────────────────────────────────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Fontes de Dados

| Fonte | Tipo | Descrição |
|-------|------|-----------|
| **AWS GuardDuty** | Ameaças | Detecção de ameaças e comportamentos anômalos |
| **AWS Security Hub** | Consolidação | Agregação de findings de múltiplos serviços |
| **AWS Inspector** | Vulnerabilidades | Avaliação de vulnerabilidades em recursos |
| **AWS CloudTrail** | Auditoria | Logs de atividades e chamadas de API |
| **CloudFlare WAF** | Proteção Web | Eventos de segurança de aplicações web |
| **AWS Config** | Conformidade | Avaliação de configurações |

### 1.4 Níveis de Severidade

| Severidade | Cor | SLA de Resposta | Descrição |
|------------|-----|-----------------|-----------|
| **CRITICAL** | 🔴 Vermelho | 15 minutos | Incidente ativo, impacto imediato na operação |
| **HIGH** | 🟠 Laranja | 1 hora | Ameaça significativa, ação urgente necessária |
| **MEDIUM** | 🟡 Amarelo | 4 horas | Risco moderado, requer análise |
| **LOW** | 🟢 Verde | 24 horas | Baixo risco, pode ser agendado |
| **INFO** | 🔵 Azul | 72 horas | Informativo, para conhecimento |

---

## 2. Módulo de Eventos

### 2.1 Descrição

O módulo de **Eventos** é a primeira camada de visibilidade do SIEM, exibindo todos os eventos de segurança coletados das diversas fontes configuradas. Eventos são registros brutos que indicam atividades no ambiente monitorado.

### 2.2 Acesso ao Módulo

```
Menu Principal → Security Operations → Eventos
URL: /events
```

### 2.3 Interface Principal

#### 2.3.1 Dashboard de Estatísticas

| Indicador | Descrição |
|-----------|-----------|
| **Total de Eventos** | Número total de eventos no período selecionado |
| **Críticos** | Quantidade de eventos com severidade CRITICAL |
| **Alta Severidade** | Quantidade de eventos com severidade HIGH |
| **Fontes Únicas** | Número de fontes distintas gerando eventos |

#### 2.3.2 Gráficos

- **Eventos por Severidade**: Distribuição proporcional (Pie Chart)
- **Top 10 Tipos de Eventos**: Eventos mais frequentes (Bar Chart)
- **Timeline de Eventos (24h)**: Tendência temporal de eventos

### 2.4 Funcionalidades de Busca e Filtro

#### 2.4.1 Campo de Busca Principal

**Localização**: Parte superior da área de filtros

**Sintaxe de Busca**:

| Tipo de Busca | Exemplo | Descrição |
|---------------|---------|-----------|
| Busca por CVE | `CVE-2024-45337` | Busca exata pelo identificador CVE |
| Busca por texto | `login failed` | Busca em descrição e campos de texto |
| Busca por IP | `192.168.1.100` | Busca por endereço IP específico |
| Busca por tipo | `Software and Configuration` | Busca por tipo de evento |

**Operação**:
1. Digite o termo de busca no campo
2. Pressione **Enter** ou clique em **BUSCAR**
3. O botão **X** limpa a busca atual

#### 2.4.2 Filtros Disponíveis

| Filtro | Opções | Descrição |
|--------|--------|-----------|
| **Severidade** | CRITICAL, HIGH, MEDIUM, LOW, INFO | Filtra por nível de criticidade |
| **Tipo** | Dinâmico (baseado em dados) | Filtra por categoria do evento |
| **Origem** | AWS Security Hub, GuardDuty, Inspector, etc. | Filtra pela fonte do evento |

**Operação de Filtros**:
1. Selecione uma ou mais opções em cada dropdown
2. A seleção é cumulativa (múltiplos filtros simultâneos)
3. Clique em **BUSCAR** para aplicar
4. Limpe filtros individualmente clicando no X de cada seleção

### 2.5 Tabela de Eventos

#### 2.5.1 Colunas Disponíveis

| Coluna | Descrição | Ordenável |
|--------|-----------|-----------|
| **Data/Hora** | Timestamp do evento em formato local | ✅ |
| **Severidade** | Nível de criticidade com cor indicativa | ✅ |
| **Tipo** | Classificação/categoria do evento | ✅ |
| **Origem** | Fonte que gerou o evento | ✅ |
| **Descrição** | Resumo do evento (truncado se extenso) | ❌ |
| **Ações** | Botão para visualizar detalhes | ❌ |

#### 2.5.2 Seleção de Eventos

- **Checkbox individual**: Seleciona evento específico
- **Checkbox do cabeçalho**: Seleciona todos os eventos da página
- **Contador de seleção**: Exibe quantidade de eventos selecionados
- **Limpar Seleção**: Botão para desmarcar todos

### 2.6 Detalhes do Evento

Ao clicar no ícone 👁️ (Visualizar), um dialog exibe informações completas:

| Seção | Campos |
|-------|--------|
| **Identificação** | ID, Timestamp, Tipo |
| **Classificação** | Severidade, Origem, Tags |
| **Conteúdo** | Descrição completa |
| **Metadados** | IP de origem, Usuário, Detalhes técnicos |

### 2.7 Exportação de Dados

**Formatos disponíveis**:
- **CSV**: Planilha para análise em Excel/Sheets
- **JSON**: Formato estruturado para integração

**Escopo da exportação**:
- Se eventos selecionados: Exporta apenas seleção
- Se nenhuma seleção: Exporta com filtros atuais aplicados

### 2.8 Indicador de Dados em Tempo Real

| Indicador | Significado |
|-----------|-------------|
| 🟢 **LIVE DATA • agora** | Dados reais do OpenSearch |
| 🟡 **MOCK DATA** | Dados de demonstração |
| 🔴 **OFFLINE** | Sem conexão com backend |

---

## 3. Módulo de Alertas

### 3.1 Descrição

O módulo de **Alertas** representa eventos que foram elevados a um nível de atenção superior, seja por regras automatizadas ou por correlação de eventos. Alertas requerem análise e possível ação de resposta.

### 3.2 Acesso ao Módulo

```
Menu Principal → Security Operations → Alertas
URL: /alerts
```

### 3.3 Interface Principal

#### 3.3.1 Dashboard de Estatísticas

| Indicador | Descrição |
|-----------|-----------|
| **Total de Alertas** | Número total de alertas registrados |
| **Alertas Ativos** | Alertas com status "Ativo" |
| **Triggers (24h)** | Alertas disparados nas últimas 24 horas |
| **Alertas Inativos** | Alertas já tratados/fechados |

#### 3.3.2 Gráfico de Distribuição

- **Alertas por Severidade**: Distribuição proporcional dos alertas ativos

### 3.4 Funcionalidades de Busca e Filtro

#### 3.4.1 Campo de Busca por CVE

**Localização**: Topo da área de filtros (campo em destaque)

**Funcionalidade Especial para CVE**:
- Busca **EXATA** quando o termo começa com "CVE-"
- Formato: `CVE-YYYY-NNNNN` (ex: CVE-2024-45337)
- Pressione **Enter** para busca imediata
- Debounce de 500ms para busca automática enquanto digita

**Exemplo de Uso**:
```
1. Digite: CVE-2024-45337
2. Pressione Enter (ou aguarde 500ms)
3. Sistema retorna APENAS alertas com esse CVE específico
```

#### 3.4.2 Filtros Disponíveis

| Filtro | Opções | Descrição |
|--------|--------|-----------|
| **Severidade** | CRITICAL, HIGH, MEDIUM, LOW, INFO | Múltipla seleção |
| **Origem** | GuardDuty, Security Hub, Inspector, CloudTrail, CloudFlare | Múltipla seleção |
| **Status** | Ativo, Inativo | Múltipla seleção |

### 3.5 Tabela de Alertas

#### 3.5.1 Colunas

| Coluna | Descrição |
|--------|-----------|
| **Nome** | Título descritivo do alerta (inclui CVE se aplicável) |
| **Severidade** | Chip colorido indicando criticidade |
| **Origem** | Chip colorido indicando a fonte |
| **Status** | Ativo/Inativo |
| **Último Trigger** | Data/hora do último disparo |
| **Ações** | Visualizar, Editar, Deletar |

#### 3.5.2 Código de Cores por Origem

| Origem | Cor |
|--------|-----|
| **GuardDuty** | 🟠 Laranja |
| **Security Hub** | 🔵 Azul |
| **Inspector** | 🟣 Roxo |
| **CloudTrail** | 🟢 Verde |
| **CloudFlare** | 🟠 Laranja escuro |

### 3.6 Detalhes do Alerta

Ao clicar em um alerta, o dialog de detalhes exibe:

| Seção | Informações |
|-------|-------------|
| **Cabeçalho** | Nome, Severidade, Origem, Status |
| **Descrição** | Texto descritivo completo do alerta |
| **Informações da Origem** | Origem, Categoria, Região, Conta AWS |
| **Detalhes Adicionais** | Source ID, Resource ID, Resource Type |
| **Recomendação** | Sugestão de ação (quando disponível) |

### 3.7 Ações sobre Alertas

#### 3.7.1 Criar Caso a partir de Alerta

**Quando usar**: Quando o alerta requer investigação formal

**Procedimento**:
1. Visualize o alerta
2. Clique em **Criar Caso**
3. Preencha informações adicionais
4. Confirme a criação

#### 3.7.2 Alterar Status

**Opções**:
- **Ativo**: Alerta requer atenção
- **Inativo**: Alerta tratado/descartado

#### 3.7.3 Deletar Alerta

**Atenção**: Ação irreversível. Use apenas para alertas falso-positivos confirmados.

### 3.8 Criação de Novo Alerta Manual

**Botão**: `+ NOVO ALERTA` (canto superior direito)

**Campos obrigatórios**:
- Nome do alerta
- Severidade
- Descrição

**Campos opcionais**:
- Categoria
- Configuração de notificações

---

## 4. Módulo de Casos

### 4.1 Descrição

O módulo de **Casos** representa incidentes de segurança que estão sendo formalmente investigados. Um caso pode ser originado de alertas, eventos ou criado manualmente, e segue um ciclo de vida definido até sua resolução.

### 4.2 Acesso ao Módulo

```
Menu Principal → Security Operations → Casos
URL: /cases
```

### 4.3 Interface Principal

#### 4.3.1 Dashboard de Estatísticas

| Indicador | Descrição |
|-----------|-----------|
| **Total de Casos** | Número total de casos registrados |
| **Novos** | Casos recém-criados aguardando triagem |
| **Em Andamento** | Casos em investigação ativa |
| **Resolvidos** | Casos com investigação concluída |
| **Fechados** | Casos finalizados |

#### 4.3.2 Gráficos

- **Casos por Status**: Distribuição proporcional
- **Casos por Severidade**: Distribuição de criticidade

### 4.4 Ciclo de Vida de um Caso

```
┌─────────┐    ┌─────────────┐    ┌───────────┐    ┌─────────┐
│   NEW   │───▶│ IN_PROGRESS │───▶│ RESOLVED  │───▶│ CLOSED  │
│ (Novo)  │    │(Em Andamento)│   │(Resolvido)│    │(Fechado)│
└─────────┘    └─────────────┘    └───────────┘    └─────────┘
     │                │                  │
     │                │                  │
     └────────────────┴──────────────────┘
            (Pode voltar se necessário)
```

| Status | Descrição | Responsável |
|--------|-----------|-------------|
| **NEW** | Caso criado, aguardando análise inicial | Analista L1 |
| **IN_PROGRESS** | Investigação em andamento | Analista L2/L3 |
| **RESOLVED** | Investigação concluída, pendente validação | Analista responsável |
| **CLOSED** | Caso finalizado | Supervisor |

### 4.5 Filtros de Casos

| Filtro | Opções |
|--------|--------|
| **Status** | NEW, IN_PROGRESS, RESOLVED, CLOSED |
| **Severidade** | CRITICAL, HIGH, MEDIUM, LOW |
| **Responsável** | Lista de analistas |
| **Busca** | Texto livre (título, descrição) |

### 4.6 Tabela de Casos

#### 4.6.1 Colunas

| Coluna | Descrição |
|--------|-----------|
| **Título** | Nome descritivo do caso |
| **Severidade** | Criticidade atribuída |
| **Status** | Estado atual do ciclo de vida |
| **Responsável** | Analista atribuído |
| **Criado em** | Data de criação |
| **Atualizado em** | Última modificação |
| **Ações** | Visualizar detalhes |

### 4.7 Detalhes do Caso

Ao clicar em um caso, uma tela completa de detalhes é exibida:

#### 4.7.1 Informações Gerais

- Título e ID do caso
- Severidade e Status
- Analista responsável
- Datas de criação/atualização

#### 4.7.2 Descrição

- Resumo executivo do incidente
- Contexto e background

#### 4.7.3 Timeline/Atividades

Histórico cronológico de:
- Comentários adicionados
- Mudanças de status
- Atribuições
- Anexos incluídos
- Execuções de playbooks

#### 4.7.4 Alertas Relacionados

Lista de alertas que originaram ou estão associados ao caso.

#### 4.7.5 Evidências

Arquivos e documentos anexados como evidência.

### 4.8 Criação de Casos

#### 4.8.1 A partir de Alerta

1. No módulo Alertas, visualize o alerta
2. Clique em **Criar Caso**
3. Sistema pré-preenche informações do alerta
4. Adicione contexto adicional se necessário
5. Confirme a criação

#### 4.8.2 A partir de Evento

1. No módulo Eventos, selecione o evento
2. Use a opção **Criar Caso**
3. Preencha título e descrição
4. Defina severidade e responsável
5. Confirme a criação

#### 4.8.3 Criação Manual

1. Clique em **+ NOVO CASO**
2. Preencha:
   - Título (obrigatório)
   - Descrição (obrigatório)
   - Severidade (obrigatório)
   - Responsável (opcional)
3. Clique em **Criar**

### 4.9 Gerenciamento de Casos

#### 4.9.1 Atualizar Status

1. Abra os detalhes do caso
2. Clique no status atual
3. Selecione novo status
4. Adicione comentário de justificativa (recomendado)

#### 4.9.2 Adicionar Comentário

1. Na seção de Timeline
2. Digite o comentário
3. Clique em **Adicionar**
4. Comentário é registrado com autor e timestamp

#### 4.9.3 Atribuir Responsável

1. Clique no campo "Responsável"
2. Selecione analista da lista
3. Sistema registra a mudança na timeline

### 4.10 Exportação

**Formatos**:
- **CSV**: Listagem de casos
- **JSON**: Dados estruturados
- **PDF**: Relatório individual do caso (quando disponível)

---

## 5. Fluxo Operacional Integrado

### 5.1 Fluxo Padrão de Tratamento de Incidente

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FLUXO DE RESPOSTA A INCIDENTES                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
│  │ DETECÇÃO │   │ ANÁLISE  │   │ CONTENÇÃO│   │    RESOLUÇÃO     │ │
│  │ (Eventos)│──▶│ (Alertas)│──▶│  (Casos) │──▶│   (Casos)        │ │
│  └──────────┘   └──────────┘   └──────────┘   └──────────────────┘ │
│       │              │              │                │              │
│       ▼              ▼              ▼                ▼              │
│   Coleta de     Triagem e      Investigação     Documentação       │
│   evidências    priorização    e mitigação      e fechamento       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Procedimento Operacional por Severidade

#### 5.2.1 CRITICAL (Vermelho)

| Etapa | Ação | Tempo |
|-------|------|-------|
| 1 | Notificar supervisor imediatamente | 0-5 min |
| 2 | Avaliar impacto em produção | 5-10 min |
| 3 | Criar caso e iniciar contenção | 10-15 min |
| 4 | Acionar equipe de plantão se necessário | Conforme avaliação |
| 5 | Escalar para gestão se confirmado | 15-30 min |

#### 5.2.2 HIGH (Laranja)

| Etapa | Ação | Tempo |
|-------|------|-------|
| 1 | Analisar detalhes do alerta | 0-15 min |
| 2 | Verificar correlações com outros eventos | 15-30 min |
| 3 | Criar caso se necessário | 30-45 min |
| 4 | Definir plano de ação | 45-60 min |
| 5 | Iniciar remediação | Conforme plano |

#### 5.2.3 MEDIUM (Amarelo)

| Etapa | Ação | Tempo |
|-------|------|-------|
| 1 | Analisar na próxima janela de triagem | 0-2h |
| 2 | Documentar análise inicial | 2-3h |
| 3 | Determinar necessidade de caso | 3-4h |
| 4 | Agendar remediação se necessário | Próximo ciclo |

#### 5.2.4 LOW/INFO (Verde/Azul)

| Etapa | Ação | Tempo |
|-------|------|-------|
| 1 | Incluir na revisão diária | Próximo dia |
| 2 | Documentar se padrão recorrente | Conforme necessidade |
| 3 | Ajustar regras se falso-positivo | Backlog |

### 5.3 Matriz de Escalação

| Condição | Ação | Destinatário |
|----------|------|--------------|
| Alerta CRITICAL não tratado em 15min | Escalação automática | Supervisor SOC |
| Caso CRITICAL sem progresso em 30min | Notificação | Gerente de Segurança |
| Múltiplos alertas correlacionados | Criação automática de caso | Analista L2 |
| Alerta de fonte crítica (GuardDuty) | Priorização automática | Analista de plantão |

---

## 6. Boas Práticas

### 6.1 Triagem de Eventos

✅ **FAÇA**:
- Verifique o contexto antes de escalar
- Correlacione com eventos anteriores
- Documente sua análise
- Use filtros para focar em eventos relevantes

❌ **EVITE**:
- Ignorar eventos de baixa severidade sistematicamente
- Criar alertas para todo evento
- Deixar eventos sem análise por mais de 24h

### 6.2 Gerenciamento de Alertas

✅ **FAÇA**:
- Valide a origem do alerta
- Verifique se há falso-positivo recorrente
- Documente a justificativa ao alterar status
- Crie caso quando necessário aprofundamento

❌ **EVITE**:
- Marcar como inativo sem análise
- Criar múltiplos alertas para o mesmo issue
- Ignorar padrões de alertas repetitivos

### 6.3 Gestão de Casos

✅ **FAÇA**:
- Mantenha título claro e descritivo
- Atualize status em tempo real
- Adicione comentários significativos
- Documente todas as ações tomadas
- Feche apenas após validação completa

❌ **EVITE**:
- Casos sem responsável definido
- Longos períodos sem atualização
- Fechamento sem documentação de resolução
- Múltiplos casos para o mesmo incidente

### 6.4 Busca por CVE

✅ **FAÇA**:
- Use o formato exato: `CVE-YYYY-NNNNN`
- Pressione Enter para busca imediata
- Verifique tanto em Eventos quanto em Alertas

❌ **EVITE**:
- Buscar apenas por número parcial (ex: "2024-45337")
- Buscar por termos genéricos quando precisa de CVE específico

---

## 7. Troubleshooting

### 7.1 Eventos

| Problema | Causa Provável | Solução |
|----------|----------------|---------|
| Eventos não carregam | Falha de conexão OpenSearch | Verificar indicador de status; contatar infra |
| Busca retorna resultados incorretos | Busca muito ampla | Usar filtros adicionais ou busca exata |
| Exportação falha | Muitos registros | Aplicar filtros para reduzir volume |
| Timeline vazia | Período sem eventos | Verificar range de tempo selecionado |

### 7.2 Alertas

| Problema | Causa Provável | Solução |
|----------|----------------|---------|
| Busca por CVE não funciona | Formato incorreto | Usar formato `CVE-YYYY-NNNNN` |
| Alertas duplicados | Múltiplas fontes | Verificar correlação de eventos |
| Status não atualiza | Cache do browser | Refresh ou limpar cache |
| Alerta não aparece | Filtro ativo | Verificar filtros aplicados |

### 7.3 Casos

| Problema | Causa Provável | Solução |
|----------|----------------|---------|
| Caso não criado | Campos obrigatórios vazios | Preencher título, descrição, severidade |
| Timeline não atualiza | Delay de indexação | Aguardar alguns segundos e atualizar |
| Exportação incompleta | Filtros aplicados | Verificar filtros antes de exportar |
| Comentário não salvo | Erro de conexão | Verificar conectividade e tentar novamente |

### 7.4 Problemas Gerais

| Indicador | Significado | Ação |
|-----------|-------------|------|
| 🔴 Tela em branco | Erro de carregamento | Atualizar página (F5) |
| 🔴 "OpenSearch not connected" | Backend indisponível | Contatar equipe de infraestrutura |
| 🟡 "Mock Data" | Dados de demonstração | Verificar configuração de produção |
| 🔴 Timeout em buscas | Consulta muito ampla | Adicionar filtros para reduzir escopo |

---

## 8. Glossário

| Termo | Definição |
|-------|-----------|
| **Alerta** | Notificação de um evento de segurança que requer atenção |
| **Caso** | Incidente de segurança sob investigação formal |
| **CVE** | Common Vulnerabilities and Exposures - identificador padrão de vulnerabilidades |
| **Evento** | Registro de atividade capturado pelas fontes de dados |
| **False Positive** | Alerta gerado para atividade legítima |
| **GuardDuty** | Serviço AWS de detecção de ameaças |
| **Inspector** | Serviço AWS de avaliação de vulnerabilidades |
| **IOC** | Indicator of Compromise - indicador de comprometimento |
| **OpenSearch** | Engine de busca e analytics (fork do Elasticsearch) |
| **Security Hub** | Console centralizado de segurança AWS |
| **Severidade** | Classificação de criticidade de um evento/alerta/caso |
| **SIEM** | Security Information and Event Management |
| **SOC** | Security Operations Center |
| **SLA** | Service Level Agreement - acordo de nível de serviço |
| **Timeline** | Histórico cronológico de eventos/ações |
| **Triagem** | Processo de avaliação e priorização inicial |

---

## Controle de Versão do Documento

| Versão | Data | Autor | Alterações |
|--------|------|-------|------------|
| 1.0 | Jan/2026 | Equipe NAZARIUS | Criação inicial |

---

## Contatos de Suporte

| Nível | Canal | Horário |
|-------|-------|---------|
| **L1 - Operacional** | Slack #soc-operations | 24x7 |
| **L2 - Técnico** | Email: soc-tech@empresa.com | Comercial |
| **L3 - Especialista** | Plantão via PagerDuty | 24x7 |
| **Infraestrutura** | Slack #infra-support | 24x7 |

---

*Este documento é propriedade da organização e deve ser utilizado exclusivamente para fins operacionais internos.*

