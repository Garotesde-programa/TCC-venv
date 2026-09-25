#!/usr/bin/env python3
"""
Agente de IA local (Ollama) para o scanner de vulnerabilidades.

Papel do agente:
  1) Orquestração em tempo real: decide, com base nos achados parciais,
     qual checagem rodar em seguida (via tool calling). O agente NUNCA
     gera payloads novos nem executa código arbitrário - ele só pode
     chamar as funções check_* já existentes e validadas em
     scanner_site.py. Isso mantém o comportamento determinístico e
     auditável, mesmo usando um modelo de linguagem no meio do caminho.
  2) Enriquecimento de insights: depois do scan, escreve um resumo em
     linguagem natural mais rico que o heurístico existente
     (_build_ai_insights em app_web.py), sem substituir o cálculo
     determinístico de score/severidade.

Tudo aqui é OPCIONAL e falha de forma segura: se o Ollama não estiver
rodando, ou o modelo não suportar tool calling, o scanner cai de volta
para o comportamento padrão (scan() sequencial + heurística local),
sem quebrar nada.

Nenhuma dependência nova é necessária: a comunicação com o Ollama é
feita via HTTP puro (urllib), do mesmo jeito que o resto do projeto
já fala com os alvos escaneados.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

import scanner_site

# --------------------------------------------------------------------------
# Configuração (tudo ajustável por variável de ambiente, mesmo padrão do
# resto do projeto)
# --------------------------------------------------------------------------

AI_BACKEND = os.getenv('SCANNER_AI_BACKEND', 'off').strip().lower()  # 'off' | 'ollama'
OLLAMA_HOST = os.getenv('SCANNER_OLLAMA_HOST', 'http://localhost:11434').rstrip('/')
OLLAMA_MODEL = os.getenv('SCANNER_OLLAMA_MODEL', 'qwen2.5:14b')
AI_MAX_SECONDS = int(os.getenv('SCANNER_AI_MAX_SECONDS', '90'))
AI_MAX_TURNS = int(os.getenv('SCANNER_AI_MAX_TURNS', '8'))
AI_HTTP_TIMEOUT = int(os.getenv('SCANNER_AI_HTTP_TIMEOUT', '30'))

SYSTEM_PROMPT = (
    "Você é um assistente de pentest que ajuda a priorizar checagens de "
    "segurança em um scanner web autorizado. Você recebe achados parciais "
    "e uma lista de ferramentas (checagens) ainda não executadas. "
    "Escolha, uma de cada vez, a checagem mais relevante para investigar a "
    "seguir, com base em sinais já observados (stack detectada, erros, "
    "headers, etc). Você NUNCA gera payloads, exploits ou código novo - "
    "só pode chamar as ferramentas fornecidas. Quando não houver mais "
    "nada relevante para testar, ou os achados já forem suficientes, "
    "responda com texto simples (sem tool call) explicando o motivo de "
    "parar."
)

# Descrição curta de cada checagem disponível, usada tanto no schema de
# tools quanto no prompt. As chaves batem com CHECK_FUNCS em scanner_site.py.
CHECK_DESCRIPTIONS = {
    'check_security_headers': 'Verifica headers de segurança ausentes/fracos (CSP, HSTS, X-Frame-Options etc).',
    'check_sensitive_paths': 'Procura caminhos/arquivos sensíveis expostos (backups, .env, painéis admin).',
    'check_directory_listing': 'Verifica se listagem de diretório está habilitada no servidor.',
    'check_security_txt': 'Verifica presença e conteúdo do security.txt.',
    'check_sql_injection': 'Testa indícios de injeção SQL (erro-based e time-based) nos parâmetros da URL.',
    'check_xss': 'Testa Cross-Site Scripting refletido nos parâmetros da URL.',
    'check_open_redirect': 'Testa redirecionamento aberto via parâmetros suspeitos.',
    'check_http_methods': 'Verifica métodos HTTP perigosos habilitados (PUT, DELETE, TRACE...).',
    'check_cors': 'Verifica configuração de CORS (origem refletida, credentials, wildcard).',
    'check_info_disclosure': 'Procura vazamento de informação em headers/respostas (stack, versões).',
    'check_lfi': 'Testa indícios de path traversal / local file inclusion.',
    'check_cookie_security': 'Verifica flags de cookie (HttpOnly, Secure, SameSite).',
    'check_https_redirect': 'Verifica se HTTP redireciona corretamente para HTTPS.',
}

# Mapa nome->função real, construído a partir do CHECK_FUNCS já existente
# em scanner_site.py (fonte única de verdade - se um check for adicionado
# lá, ele aparece aqui automaticamente).
def _build_check_map() -> dict[str, Callable]:
    mapping: dict[str, Callable] = {}
    for _group, funcs in scanner_site.CHECK_FUNCS.items():
        for _label, func in funcs:
            mapping[func.__name__] = func
    return mapping


CHECK_MAP: dict[str, Callable] = _build_check_map()


def _build_tools_schema() -> list[dict]:
    tools = []
    for name, func in CHECK_MAP.items():
        desc = CHECK_DESCRIPTIONS.get(name, f'Executa a checagem {name}.')
        tools.append({
            'type': 'function',
            'function': {
                'name': name,
                'description': desc,
                'parameters': {
                    'type': 'object',
                    'properties': {
                        'url': {'type': 'string', 'description': 'URL alvo já validada do scan atual.'},
                    },
                    'required': ['url'],
                },
            },
        })
    return tools


TOOLS_SCHEMA = _build_tools_schema()


# --------------------------------------------------------------------------
# Cliente HTTP mínimo pro Ollama (sem dependências novas)
# --------------------------------------------------------------------------

class AgentUnavailable(Exception):
    """Ollama não está acessível ou respondeu de forma inesperada."""


def is_enabled() -> bool:
    return AI_BACKEND == 'ollama'


def is_available(timeout: int = 3) -> bool:
    """Checagem rápida de saúde - usada antes de tentar orquestrar."""
    if not is_enabled():
        return False
    try:
        req = urllib.request.Request(f'{OLLAMA_HOST}/api/tags', method='GET')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ollama_chat(messages: list[dict], tools: Optional[list[dict]] = None) -> dict:
    payload = {
        'model': OLLAMA_MODEL,
        'messages': messages,
        'stream': False,
    }
    if tools:
        payload['tools'] = tools

    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        f'{OLLAMA_HOST}/api/chat',
        data=data,
        method='POST',
        headers={'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(req, timeout=AI_HTTP_TIMEOUT) as resp:
            body = resp.read().decode('utf-8')
            return json.loads(body)
    except urllib.error.URLError as exc:
        raise AgentUnavailable(f'Ollama inacessível em {OLLAMA_HOST}: {exc}') from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AgentUnavailable(f'Resposta inválida do Ollama: {exc}') from exc


def _parse_tool_call_args(raw_args) -> dict:
    """Ollama normalmente já manda 'arguments' como dict, mas alguns
    modelos/versões mandam string JSON. Aceita os dois formatos."""
    if isinstance(raw_args, dict):
        return raw_args
    if isinstance(raw_args, str):
        try:
            return json.loads(raw_args)
        except json.JSONDecodeError:
            return {}
    return {}


def _findings_brief(findings: list[dict], limit: int = 12) -> str:
    """Resumo compacto dos achados pra não estourar o contexto do modelo
    a cada turno do agente."""
    if not findings:
        return 'Nenhum achado ainda.'
    lines = []
    for f in findings[-limit:]:
        lines.append(f"- [{f.get('severity', '?')}] {f.get('type', '?')}: {f.get('desc', '')[:140]}")
    return '\n'.join(lines)


# --------------------------------------------------------------------------
# Agente de orquestração em tempo real
# --------------------------------------------------------------------------

def agent_scan(
    url: str,
    checks: Optional[list[str]] = None,
    progress_cb: Optional[Callable[[str, str, str], None]] = None,
    cancel_cb: Optional[Callable[[], bool]] = None,
) -> dict:
    """
    Roda o scan deixando o agente decidir a ordem das checagens com base
    nos achados parciais. Tem o mesmo formato de retorno de
    scanner_site.scan(): {'findings': [...], 'meta': {...}}, mais um
    campo extra 'agent_log' com o raciocínio/decisões do agente (útil
    pra mostrar na UI e pra demonstração/avaliação do projeto).

    Se o Ollama não estiver disponível a qualquer momento, cai de volta
    pro scan() sequencial padrão automaticamente.
    """
    started = time.time()

    if not is_available():
        note = f'Backend de IA ({OLLAMA_MODEL} @ {OLLAMA_HOST}) indisponível - usando ordem padrão.'
        if progress_cb:
            progress_cb('agent', note, 'fallback')
        result = scanner_site.scan(url, checks, progress_cb=progress_cb, cancel_cb=cancel_cb)
        result['agent_log'] = [note]
        return result

    pending = dict(CHECK_MAP)  # nome -> função, vai encolhendo conforme executa
    all_findings: list[dict] = []
    agent_log: list[str] = []
    seen_ids: set[str] = set()

    messages = [
        {'role': 'system', 'content': SYSTEM_PROMPT},
        {'role': 'user', 'content': f'URL alvo (já validada e autorizada): {url}\nComece escolhendo a primeira checagem.'},
    ]

    for turn in range(1, AI_MAX_TURNS + 1):
        if cancel_cb and cancel_cb():
            agent_log.append('Scan cancelado pelo usuário.')
            break
        if (time.time() - started) > AI_MAX_SECONDS:
            agent_log.append(f'Orçamento de tempo do agente ({AI_MAX_SECONDS}s) esgotado.')
            break
        if not pending:
            agent_log.append('Todas as checagens disponíveis já foram executadas.')
            break

        remaining_tools = [t for t in TOOLS_SCHEMA if t['function']['name'] in pending]
        messages.append({
            'role': 'user',
            'content': (
                f'Achados até agora:\n{_findings_brief(all_findings)}\n\n'
                f'Checagens ainda não executadas: {", ".join(pending.keys())}.\n'
                'Escolha a próxima via tool call, ou responda em texto se quiser parar.'
            ),
        })

        try:
            response = _ollama_chat(messages, tools=remaining_tools)
        except AgentUnavailable as exc:
            agent_log.append(f'Agente falhou no turno {turn} ({exc}); rodando checagens restantes na ordem padrão.')
            break

        message = response.get('message', {}) or {}
        tool_calls = message.get('tool_calls') or []

        if not tool_calls:
            reasoning = (message.get('content') or '').strip()
            agent_log.append(f'Agente decidiu parar no turno {turn}: {reasoning or "sem justificativa retornada"}.')
            break

        messages.append(message)

        for call in tool_calls:
            fn = call.get('function', {})
            fn_name = fn.get('name')
            if fn_name not in pending:
                # o modelo tentou chamar algo inválido/repetido - ignora com segurança
                messages.append({'role': 'tool', 'content': f'Ferramenta {fn_name} indisponível ou já executada.'})
                continue

            func = pending.pop(fn_name)
            label = fn_name.replace('check_', '').replace('_', ' ').title()
            agent_log.append(f'Turno {turn}: agente escolheu "{fn_name}".')

            if progress_cb:
                progress_cb('agent', label, 'running')
            try:
                new_findings = func(url) or []
            except Exception as exc:
                new_findings = []
                agent_log.append(f'Checagem {fn_name} falhou: {exc}')
            if progress_cb:
                progress_cb('agent', label, 'done')

            for item in new_findings:
                if item['id'] not in seen_ids:
                    seen_ids.add(item['id'])
                    all_findings.append(item)

            messages.append({
                'role': 'tool',
                'content': json.dumps({
                    'check': fn_name,
                    'new_findings_count': len(new_findings),
                    'findings': [f.get('desc', '')[:200] for f in new_findings][:5],
                }, ensure_ascii=False),
            })

    # Roda o que sobrou (se o agente parou cedo ou não tinha Ollama), na
    # ordem padrão, respeitando o tempo e cancelamento restantes.
    if pending and not (cancel_cb and cancel_cb()):
        leftover_names = list(pending.keys())
        agent_log.append(f'Rodando checagens restantes na ordem padrão: {", ".join(leftover_names)}.')
        for fn_name in leftover_names:
            if cancel_cb and cancel_cb():
                break
            if (time.time() - started) > scanner_site.MAX_SCAN_SECONDS:
                break
            func = CHECK_MAP[fn_name]
            label = fn_name.replace('check_', '').replace('_', ' ').title()
            if progress_cb:
                progress_cb('agent', label, 'running')
            try:
                new_findings = func(url) or []
            except Exception as exc:
                new_findings = []
                agent_log.append(f'Checagem {fn_name} falhou: {exc}')
            if progress_cb:
                progress_cb('agent', label, 'done')
            for item in new_findings:
                if item['id'] not in seen_ids:
                    seen_ids.add(item['id'])
                    all_findings.append(item)

    return {
        'findings': all_findings,
        'meta': {
            'scanner_version': scanner_site.SCANNER_VERSION,
            'duration_ms': int((time.time() - started) * 1000),
            'checks_run': list(seen_ids),
            'findings_count': len(all_findings),
            'cancelled': bool(cancel_cb and cancel_cb()),
            'inconclusive': False,
            'ai_backend': OLLAMA_MODEL if is_available() else None,
        },
        'agent_log': agent_log,
    }


# --------------------------------------------------------------------------
# Enriquecimento de insights (narrativa) - complementa _build_ai_insights
# --------------------------------------------------------------------------

def enrich_insights(url: str, findings: list[dict], base_insights: dict) -> dict:
    """
    Recebe o dict já calculado por _build_ai_insights (heurística
    determinística: risk_score, risk_level, priority etc.) e pede pro
    Ollama escrever um resumo em linguagem natural mais rico, mantendo
    os números intactos. Nunca sobrescreve o score/nível - só adiciona
    um campo 'narrative_llm'. Retorna base_insights inalterado se o
    Ollama não estiver disponível (fail-safe).
    """
    if not is_available():
        return base_insights

    prompt = (
        f'URL escaneada: {url}\n'
        f"Score de risco calculado: {base_insights.get('risk_score')}/100 "
        f"({base_insights.get('risk_level')}).\n"
        f'Achados:\n{_findings_brief(findings, limit=20)}\n\n'
        'Escreva um resumo executivo curto (3-5 frases, em português) '
        'para um relatório de segurança, explicando o risco geral e o '
        'que priorizar primeiro. Não invente vulnerabilidades que não '
        'estão na lista acima. Responda só com o texto do resumo.'
    )
    try:
        response = _ollama_chat([
            {'role': 'system', 'content': 'Você escreve resumos executivos de relatórios de pentest, de forma objetiva e sem exagero.'},
            {'role': 'user', 'content': prompt},
        ])
        narrative = (response.get('message', {}) or {}).get('content', '').strip()
        if narrative:
            base_insights = dict(base_insights)
            base_insights['narrative_llm'] = narrative
            base_insights['ai_backend'] = OLLAMA_MODEL
    except AgentUnavailable:
        pass
    return base_insights


if __name__ == '__main__':
    # Teste manual rápido:
    #   SCANNER_AI_BACKEND=ollama python3 ai_agent.py https://exemplo-autorizado.com
    import sys as _sys

    if len(_sys.argv) < 2:
        print('Uso: python3 ai_agent.py <url> (defina SCANNER_AI_BACKEND=ollama antes)')
        raise SystemExit(1)

    target = _sys.argv[1]
    print(f'Backend habilitado: {is_enabled()} | Ollama disponível: {is_available()}')
    out = agent_scan(target)
    print(json.dumps(out, indent=2, ensure_ascii=False))
