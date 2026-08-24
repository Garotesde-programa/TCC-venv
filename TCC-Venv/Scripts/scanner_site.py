#!/usr/bin/env python3
"""
Scanner de Vulnerabilidades Web
Detecta: Misconfiguration, SQLi, XSS, Open Redirect, HTTP Methods, Info Disclosure
Otimizado com requisições paralelas
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
import argparse
import sys
import os
import time
import random
import hashlib
import ipaddress
import socket
import uuid
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

SCANNER_VERSION = '2.0.0'

# Configuração (ajustáveis por variáveis de ambiente)
TIMEOUT = int(os.getenv('SCANNER_TIMEOUT', '5'))
MAX_WORKERS = int(os.getenv('SCANNER_MAX_WORKERS', '12'))
SCAN_USER_AGENT = os.getenv(
    'SCANNER_USER_AGENT',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner/2.0',
)
ALLOW_PRIVATE_TARGETS = os.getenv('SCANNER_ALLOW_PRIVATE', '').lower() in ('1', 'true', 'yes')
MAX_SCAN_SECONDS = int(os.getenv('SCANNER_MAX_SCAN_SECONDS', '180'))
ALLOW_LOCALHOST_TARGETS = os.getenv('SCANNER_ALLOW_LOCALHOST', '1').lower() in ('1', 'true', 'yes')

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


CWE_BY_CHECK = {
    'sql': 'CWE-89',
    'xss': 'CWE-79',
    'lfi': 'CWE-22',
    'redirect': 'CWE-601',
    'http_methods': 'CWE-650',
    'cors': 'CWE-942',
    'misconfig': 'CWE-16',
    'info': 'CWE-200',
    'cookie': 'CWE-614',
    'https': 'CWE-319',
}

DEFAULT_CONFIDENCE = {
    'sql': 'medium',
    'xss': 'medium',
    'lfi': 'medium',
    'redirect': 'high',
    'http_methods': 'high',
    'cors': 'high',
    'misconfig': 'high',
    'info': 'high',
    'cookie': 'high',
    'https': 'high',
}

SEVERITY = {
    'sql': 'critical', 'xss': 'critical', 'lfi': 'critical',
    'http_methods': 'high', 'redirect': 'medium', 'cors': 'medium',
    'misconfig': 'medium', 'info': 'low', 'cookie': 'medium',
    'https': 'high',
}

REMEDIATION = {
    'sql': 'Use prepared statements (parameterized queries). Nunca concatene input em SQL.',
    'xss': 'Escape output (HTML entities), use CSP, valide e sanitize todo input.',
    'misconfig': 'Configure headers de segurança no servidor (X-Frame-Options, CSP, etc). Adicione security.txt em /.well-known/security.txt.',
    'redirect': 'Valide URLs de redirect contra whitelist. Não redirecione para URLs externas.',
    'http_methods': 'Desabilite métodos perigosos (PUT, DELETE, TRACE) se não forem necessários.',
    'info': 'Remova ou ofusque headers Server, X-Powered-By no servidor.',
    'lfi': 'Evite incluir arquivos baseado em input. Use whitelist de arquivos permitidos.',
    'cookie': 'Configure Set-Cookie com HttpOnly e Secure para cookies de sessão.',
    'https': 'Configure redirect 301/302 de HTTP para HTTPS no servidor.',
    'cors': 'Use Access-Control-Allow-Origin com origens específicas, nunca * com credenciais.',
}


def _finding_fingerprint(check_key: str, desc: str, stable_key: str | None = None) -> str:
    raw = f'{check_key}|{stable_key}'.encode('utf-8', errors='ignore') if stable_key else f'{check_key}|{desc}'.encode('utf-8', errors='ignore')
    return hashlib.sha256(raw).hexdigest()[:16]


_PARAM_RE = re.compile(r'\?([A-Za-z0-9_\.\-\[\]]+)=')


def _extract_stable_key(check_key: str, desc: str) -> str | None:
    """Extrai um identificador estável (ex: nome do parâmetro) do texto do
    achado, pra não gerar um fingerprint novo a cada scan só porque o
    trecho de resposta capturado no desc mudou (payload diferente, resposta
    dinâmica, etc). Usado no histórico/trend (_build_comparison)."""
    m = _PARAM_RE.search(desc)
    if m:
        return f'param:{m.group(1)}'
    if check_key == 'misconfig':
        m2 = re.search(r'Possível exposição: (\S+)', desc)
        if m2:
            return f'path:{m2.group(1)}'
        m3 = re.search(r'Header ausente: (\S+)', desc)
        if m3:
            return f'header:{m3.group(1)}'
    return None


def make_finding(
    check_key: str,
    category_label: str,
    desc: str,
    *,
    severity: str | None = None,
    remediation: str | None = None,
    confidence: str | None = None,
    evidence: dict | None = None,
    target_url: str | None = None,
) -> dict:
    sev = severity or SEVERITY.get(check_key, 'medium')
    rem = remediation if remediation is not None else REMEDIATION.get(check_key, 'Consulte documentação de segurança.')
    ev = dict(evidence or {})
    if target_url and 'request_example' not in ev:
        ev['request_example'] = f'GET {target_url}'
    if desc and 'response_signal' not in ev:
        ev['response_signal'] = desc[:220]
    return {
        'id': _finding_fingerprint(check_key, desc, _extract_stable_key(check_key, desc)),
        'type': category_label,
        'check': check_key,
        'desc': desc,
        'severity': sev,
        'remediation': rem,
        'cwe': CWE_BY_CHECK.get(check_key, 'CWE-693'),
        'confidence': confidence or DEFAULT_CONFIDENCE.get(check_key, 'medium'),
        'evidence': ev,
    }


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Regra única de bloqueio de IP, usada tanto para o host literal quanto para
    todo IP resolvido via DNS (evita bypass por DNS rebinding).
    Nota: no módulo ipaddress, is_private também é True para endereços de
    loopback - por isso loopback é resolvido e retorna ANTES de cair no
    branch de is_private, para não ser bloqueado em duplicidade quando
    ALLOW_LOCALHOST_TARGETS=1 mas ALLOW_PRIVATE_TARGETS=0 (configuração padrão)."""
    if ip.is_loopback:
        return None if ALLOW_LOCALHOST_TARGETS else 'Alvo em loopback não permitido'
    if (ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast
            or ip.is_unspecified) and not ALLOW_PRIVATE_TARGETS:
        return 'Alvo em rede privada/reservada bloqueado (use SCANNER_ALLOW_PRIVATE=1 com autorização)'
    return None


def _host_is_blocked(host: str) -> str | None:
    """Valida o host literal da URL (sem DNS). Mantido para checagem rápida antes
    de resolver — a validação definitiva (que cobre DNS rebinding) é
    `_resolve_and_validate_host`."""
    host = (host or '').strip().lower().rstrip('.')
    if not host:
        return 'Host inválido na URL'
    if host in ('localhost', '127.0.0.1', '::1'):
        if not ALLOW_LOCALHOST_TARGETS:
            return 'Varredura em localhost desabilitada (SCANNER_ALLOW_LOCALHOST=0)'
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    return _ip_is_blocked(ip)


def _resolve_and_validate_host(host: str) -> str | None:
    """
    Resolve o hostname via DNS e valida CADA IP retornado.
    Isso fecha o bypass de DNS rebinding: um domínio público que aponta
    (ou passa a apontar, via TTL curto) para 127.0.0.1/rede interna não passa
    despendo apenas de checagem lexical do hostname.
    Retorna mensagem de erro, ou None se o host for seguro para uso.
    """
    host = (host or '').strip().lower().rstrip('.')
    if not host:
        return 'Host inválido na URL'
    if host in ('localhost',):
        return _host_is_blocked(host)
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return 'Não foi possível resolver o host (DNS)'
    except Exception:
        return 'Falha ao resolver o host'
    if not infos:
        return 'Não foi possível resolver o host (DNS)'
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        blocked = _ip_is_blocked(ip)
        if blocked:
            return f'{blocked} (host {host} resolve para {addr})'
    return None


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Revalida o host de destino a cada hop de redirect, para que um alvo
    validado no início não possa redirecionar para um IP interno depois."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        host = (parsed.netloc or '').split(':')[0]
        if _resolve_and_validate_host(host):
            return None  # aborta o redirect silenciosamente (trata como sem novo request)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SAFE_OPENER = urllib.request.build_opener(
    SafeRedirectHandler,
    urllib.request.HTTPSHandler(context=SSL_CONTEXT),
)


def validate_scan_target(url: str) -> tuple[str | None, str | None]:
    """
    Valida e normaliza URL de varredura.
    Retorna (url_normalizada, mensagem_erro).
    """
    raw = (url or '').strip()
    if not raw:
        return None, 'URL é obrigatória'
    if len(raw) > 2048:
        return None, 'URL muito longa'
    if not raw.startswith(('http://', 'https://')):
        raw = 'https://' + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ('http', 'https'):
        return None, 'Apenas HTTP/HTTPS são suportados'
    host = (parsed.netloc or '').split(':')[0]
    blocked = _host_is_blocked(host)
    if blocked:
        return None, blocked
    # Validação forte: resolve DNS e checa todo IP retornado (fecha DNS rebinding).
    blocked = _resolve_and_validate_host(host)
    if blocked:
        return None, blocked
    path = parsed.path or '/'
    normalized = f'{parsed.scheme}://{parsed.netloc}{path}'
    if parsed.query:
        normalized += f'?{parsed.query}'
    return normalized, None


def make_request(url, data=None, method='GET', headers=None):
    """Faz requisição HTTP"""
    req_headers = {
        'User-Agent': SCAN_USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
    }
    if headers:
        req_headers.update(headers)
    try:
        if data and method == 'POST':
            data = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(url, data=data, headers=req_headers, method='POST')
        else:
            req = urllib.request.Request(url, headers=req_headers, method=method)
        resp = _SAFE_OPENER.open(req, timeout=TIMEOUT)
        return resp.read().decode('utf-8', errors='ignore'), resp.headers, resp.getcode()
    except urllib.error.HTTPError as e:
        h = e.headers if hasattr(e, 'headers') else {}
        return (e.read().decode('utf-8', errors='ignore') if e.fp else None), h, e.code
    except Exception:
        return None, {}, None


# ============ MISCONFIGURATION (paralelo) ============

def _get_soft_404_baseline(base_url: str) -> tuple[int | None, str]:
    """
    Requisita DOIS paths aleatórios que quase certamente não existem e mantém
    o conteúdo (não só o tamanho) de um deles. Muitos sites (SPAs, WordPress,
    Nginx mal configurado) respondem 200 para QUALQUER path ("soft 404"), o
    que faria check_sensitive_paths reportar .git/.env/backup.sql em
    praticamente qualquer alvo. Comparar o CONTEÚDO (não só o tamanho) evita
    o caso em que uma exposição real coincide em tamanho com a página de
    soft-404 por acaso.
    Retorna (status_code_baseline, conteudo_baseline).
    """
    probe = f'/__scanner_baseline_{uuid.uuid4().hex[:12]}__'
    content, _, code = make_request(urljoin(base_url, probe))
    return code, (content or '')


def _looks_like_soft_404(content: str, baseline_content: str) -> bool:
    if not baseline_content:
        return False
    if content == baseline_content:
        return True
    # conteúdo pode ter timestamp/nonce dinâmico - usa similaridade estrutural,
    # não só tamanho, pra não confundir arquivo curto real com página curta genérica.
    import difflib
    ratio = difflib.SequenceMatcher(None, content[:2000], baseline_content[:2000]).quick_ratio()
    return ratio > 0.9


def _check_path(args):
    base_url, path, desc, baseline_code, baseline_content = args
    try:
        full_url = urljoin(base_url, path)
        content, _, code = make_request(full_url)
        if not content or code != 200 or len(content) <= 10:
            return None
        if baseline_code == 200 and _looks_like_soft_404(content, baseline_content):
            return None
        return f"Possível exposição: {path} - {desc}"
    except Exception:
        pass
    return None


def check_sensitive_paths(base_url):
    sensitive = [
        ('/.git/config', 'Repositório Git exposto'),
        ('/.git/HEAD', 'Repositório Git exposto'),
        ('/.env', 'Arquivo de ambiente exposto'),
        ('/.env.local', 'Arquivo de ambiente exposto'),
        ('/.env.production', 'Arquivo de ambiente exposto'),
        ('/phpinfo.php', 'phpinfo exposto'),
        ('/phpinfo', 'phpinfo exposto'),
        ('/server-status', 'Status do servidor Apache'),
        ('/server-info', 'Info do servidor Apache'),
        ('/admin', 'Painel admin'),
        ('/administrator', 'Painel admin'),
        ('/wp-admin', 'WordPress admin'),
        ('/wp-config.php', 'Config WordPress'),
        ('/backup.sql', 'Backup de banco de dados'),
        ('/dump.sql', 'Dump de banco'),
        ('/.htaccess', 'Configuração Apache'),
        ('/web.config', 'Configuração IIS'),
        ('/config.php', 'Config PHP'),
        ('/config.json', 'Config JSON'),
        ('/.aws/credentials', 'Credenciais AWS'),
        ('/debug', 'Debug exposto'),
        ('/trace.axd', 'Trace ASP.NET'),
        ('/.svn/entries', 'Repositório SVN'),
        ('/crossdomain.xml', 'Flash crossdomain'),
        ('/clientaccesspolicy.xml', 'Silverlight policy'),
    ]
    findings = []
    baseline_code, baseline_content = _get_soft_404_baseline(base_url)
    tasks = [(base_url, p, d, baseline_code, baseline_content) for p, d in sensitive]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for r in ex.map(_check_path, tasks):
            if r:
                findings.append(r)
    return findings


def _is_localhost(parsed_or_url):
    """True se o host for 127.0.0.1 ou localhost (scanner apontando para a própria UI)."""
    if hasattr(parsed_or_url, 'netloc'):
        host = (parsed_or_url.netloc or '').split(':')[0].lower()
    else:
        parsed = urlparse(parsed_or_url)
        host = (parsed.netloc or '').split(':')[0].lower()
    return host in ('127.0.0.1', 'localhost', '')


def check_security_headers(url):
    """Alguns servidores só mandam CSP/security headers na resposta GET
    (renderização real), não no HEAD (usado em cache/CDN). Checar só HEAD
    gera falso positivo de 'header ausente'. Considera ausente apenas se
    faltar em AMBOS os métodos."""
    findings = []
    parsed = urlparse(url)
    if _is_localhost(parsed):
        return findings

    required = {
        'X-Frame-Options': 'Proteção contra clickjacking',
        'X-Content-Type-Options': 'Proteção contra MIME sniffing',
        'Content-Security-Policy': 'Política de segurança de conteúdo',
        'Strict-Transport-Security': 'Forçar HTTPS',
    }
    recommended = {
        'Referrer-Policy': 'Controle de vazamento de referrer',
        'Permissions-Policy': 'Controle de features do browser',
    }

    headers_seen = {}
    got_any_response = False
    for method in ('HEAD', 'GET'):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': SCAN_USER_AGENT}, method=method)
            with _SAFE_OPENER.open(req, timeout=TIMEOUT) as resp:
                got_any_response = True
                for h in list(required) + list(recommended):
                    if resp.headers.get(h):
                        headers_seen[h] = True
        except urllib.error.HTTPError as e:
            got_any_response = True
            for h in list(required) + list(recommended):
                if e.headers and e.headers.get(h):
                    headers_seen[h] = True
        except Exception:
            pass

    if not got_any_response:
        return ["Erro ao verificar headers: alvo não respondeu a HEAD nem GET"]

    for header, desc in required.items():
        if not headers_seen.get(header):
            findings.append(f"Header ausente: {header} ({desc})")
    for header, desc in recommended.items():
        if not headers_seen.get(header):
            findings.append(f"Header recomendado ausente: {header} ({desc})")
    return findings


def check_directory_listing(url):
    content, _, code = make_request(url)
    if content and code == 200:
        if any(x in content.lower() for x in ['index of', '[dir]', 'parent directory']):
            return [f"Listagem de diretório habilitada"]
    return []


# ============ SQL INJECTION (paralelo) ============

SQL_ERRORS = (
    "sql syntax", "mysql_fetch", "mysqli", "postgresql", "sqlite", "ora-01",
    "sqlstate", "unclosed quotation", "warning: mysql", "pg_query", "mssql",
    "syntax error", "mysql_num_rows", "mysql_error", "odbc_", "driver",
    "sqlexception", "sqlite3", "sql_exec", "mysql_query", "pg_exec",
    "ora-00933", "ora-01756", "pl/sql", "oci_", "unexpected end of sql",
)

SQL_PAYLOADS = [
    "'", "' OR '1'='1", "' OR 1=1--", "1' OR '1'='1' /*", "admin'--",
    "1; DROP TABLE users--", "1 UNION SELECT NULL--", "' OR ''='",
    "1' AND '1'='1", "' UNION SELECT 1,2,3--", "1' ORDER BY 1--",
    "1' AND 1=2 UNION SELECT * FROM users--",
    "' OR EXISTS(SELECT * FROM users)--", "1' RLIKE (SELECT",
]

# Payloads de blind SQLi por tempo, testados à parte (medindo latência,
# não string de erro - erro nunca aparece nesse tipo de injeção).
SQL_TIME_PAYLOADS = [
    "' WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5)--",
    "1' AND SLEEP(5)--",
]
SQL_TIME_DELAY_S = 5
SQL_TIME_THRESHOLD_S = 4.0  # margem abaixo do delay do payload, tolera jitter de rede


def _test_sql(args):
    base_url, param_name, payload, all_params = args
    test_params = {k: (payload if k == param_name else v[0]) for k, v in all_params.items()}
    test_url = base_url + '?' + urllib.parse.urlencode(test_params)
    content, _, _ = make_request(test_url)
    if content:
        for err in SQL_ERRORS:
            if err in content.lower():
                return (param_name, f"Possível SQLi em ?{param_name}= - Erro: {err[:25]}...")
    return None


def _test_sql_time(args):
    """Testa blind SQLi por tempo: mede latência com payload de delay vs.
    baseline (mesmo request com valor inofensivo). Confirma 2x para reduzir
    falso positivo por lentidão pontual de rede."""
    base_url, param_name, payload, all_params = args

    baseline_params = {k: (v[0] if k != param_name else '1') for k, v in all_params.items()}
    baseline_url = base_url + '?' + urllib.parse.urlencode(baseline_params)
    t0 = time.perf_counter()
    make_request(baseline_url)
    baseline_elapsed = time.perf_counter() - t0

    test_params = {k: (payload if k == param_name else v[0]) for k, v in all_params.items()}
    test_url = base_url + '?' + urllib.parse.urlencode(test_params)

    def _elapsed_once():
        t0 = time.perf_counter()
        make_request(test_url)
        return time.perf_counter() - t0

    first = _elapsed_once()
    if (first - baseline_elapsed) < SQL_TIME_THRESHOLD_S:
        return None
    # confirma numa segunda tentativa antes de reportar
    second = _elapsed_once()
    if (second - baseline_elapsed) < SQL_TIME_THRESHOLD_S:
        return None
    return (param_name, f"Possível SQLi cega (time-based) em ?{param_name}= - "
                         f"atraso confirmado em 2 tentativas (~{first:.1f}s / ~{second:.1f}s)")


def check_sql_injection(url):
    parsed = urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        params = {'id': ['1'], 'q': ['test']}
    base_url = url.split('?')[0]

    tasks = []
    for pname, vals in params.items():
        for payload in SQL_PAYLOADS:
            tasks.append((base_url, pname, payload, {k: v for k, v in params.items()}))

    findings = []
    seen = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for r in ex.map(_test_sql, tasks):
            if r and r[0] not in seen:
                seen.add(r[0])
                findings.append(r[1])

    # Blind por tempo: sequencial por parâmetro (cada teste já é ~10-20s com
    # confirmação dupla; paralelizar demais aqui só sobrecarrega o alvo).
    time_tasks = [
        (base_url, pname, payload, {k: v for k, v in params.items()})
        for pname in params for payload in SQL_TIME_PAYLOADS
        if pname not in seen
    ]
    with ThreadPoolExecutor(max_workers=min(4, MAX_WORKERS)) as ex:
        for r in ex.map(_test_sql_time, time_tasks):
            if r and r[0] not in seen:
                seen.add(r[0])
                findings.append(r[1])

    return findings[:8]


# ============ XSS (paralelo) ============

XSS_PAYLOADS = [
    '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
    "javascript:alert(1)", "'-alert(1)-'", '<body onload=alert(1)>', '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>', "'\"-->", '<iframe src="javascript:alert(1)">',
    '<input onfocus=alert(1) autofocus>', '<marquee onstart=alert(1)>',
    '"><svg/onload=alert(1)>', "';alert(1);//", '{{constructor.constructor("alert(1)")()}}',
]


def _test_xss(args):
    base_url, param_name, payload, all_params = args
    test_params = {k: (payload if k == param_name else v[0]) for k, v in all_params.items()}
    test_url = base_url + '?' + urllib.parse.urlencode(test_params)
    content, _, _ = make_request(test_url)
    if content:
        sanitized = payload.replace('<', '&lt;').replace('>', '&gt;')
        if payload in content and sanitized not in content:
            return (param_name, f"Possível XSS em ?{param_name}= - Payload refletido sem escape")
        if re.search(r'<script|onerror|onload', content, re.I):
            return (param_name, f"Possível XSS em ?{param_name}= - Tag/evento na resposta")
    return None


def check_xss(url):
    parsed = urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        params = {'q': ['test'], 'search': ['a']}
    base_url = url.split('?')[0] if '?' in url else url

    tasks = [(base_url, p, payload, params) for p in params for payload in XSS_PAYLOADS]
    findings = []
    seen = set()
    candidates = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for r in ex.map(_test_xss, tasks):
            if r and r[0] not in seen:
                seen.add(r[0])
                candidates.append(r)

    confirmed_params = set()
    if candidates:
        try:
            confirmed_params = _confirm_xss_browser(base_url, params, [c[0] for c in candidates])
        except Exception:
            confirmed_params = set()

    for pname, desc in candidates:
        if pname in confirmed_params:
            findings.append(f"{desc} - CONFIRMADO por execução em browser real (alert disparado)")
        else:
            findings.append(f"{desc} [não confirmado em browser - pode ser falso positivo]")
    return findings[:8]


def _confirm_xss_browser(base_url: str, params: dict, param_names: list) -> set:
    """
    Abre cada candidato num Chromium headless e escuta o evento `dialog`
    (alert/confirm/prompt). Só nesse caso o JS realmente executou -
    diferente do teste por regex/reflexão, que pode dar falso positivo
    (payload dentro de comentário HTML, atributo já fechado, JSON escapado etc.)
    e falso negativo (reflexão que só executa após parse do DOM).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return set()

    confirmed = set()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            for pname in set(param_names):
                page = browser.new_page()
                triggered = {'v': False}
                page.on('dialog', lambda d: (triggered.__setitem__('v', True), d.dismiss()))
                test_params = {k: (XSS_CONFIRM_PAYLOAD if k == pname else v[0]) for k, v in params.items()}
                test_url = base_url + '?' + urllib.parse.urlencode(test_params)
                try:
                    page.goto(test_url, timeout=int(TIMEOUT * 1000), wait_until='load')
                    page.wait_for_timeout(400)
                except Exception:
                    pass
                if triggered['v']:
                    confirmed.add(pname)
                page.close()
        finally:
            browser.close()
    return confirmed


XSS_CONFIRM_PAYLOAD = '<script>alert(document.domain)</script>'


# ============ OPEN REDIRECT ============

REDIRECT_PARAMS = [
    'redirect', 'url', 'next', 'return', 'returnUrl', 'dest', 'redir',
    'goto', 'target', 'link', 'ref', 'continue', 'out', 'view', 'to',
    'redirect_uri', 'redirect_url', 'callback', 'return_url', 'return_to',
]
REDIRECT_PAYLOAD = 'https://evil.com'
REDIRECT_MARKER = 'evil.com'
REDIRECT_PAYLOAD_VARIANTS = [
    'https://evil.com',
    '//evil.com',
    '/\\evil.com',
    '\\\\evil.com',
    'https:evil.com',
    'https:/evil.com',
    '/%09/evil.com',
    'https://legitimo.com.evil.com',
    'https://evil.com%23.legitimo.com',
    'https://evil.com?.legitimo.com',
]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _test_redirect(args):
    base_url, param, payload = args
    sep = '&' if '?' in base_url else '?'
    test_url = base_url + sep + param + '=' + urllib.parse.quote(payload, safe='')
    opener = urllib.request.build_opener(NoRedirectHandler, urllib.request.HTTPSHandler(context=SSL_CONTEXT))
    try:
        req = urllib.request.Request(test_url, headers={'User-Agent': SCAN_USER_AGENT})
        opener.open(req, timeout=TIMEOUT)
        return None
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            loc = e.headers.get('Location', '') or ''
            if REDIRECT_MARKER in loc.lower():
                return f"Open Redirect em ?{param}= - payload '{payload}' -> Location: {loc[:120]}"
    except Exception:
        pass
    return None


def check_open_redirect(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + ('?' + parsed.query if parsed.query else '')
    tasks = [(base, p, payload) for p in REDIRECT_PARAMS for payload in REDIRECT_PAYLOAD_VARIANTS]
    findings = []
    seen = set()
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(_test_redirect, tasks):
            if r:
                key = r.split(' - payload')[0]
                if key not in seen:
                    seen.add(key)
                    findings.append(r)
    return findings[:6]


# ============ HTTP METHODS ============

def check_http_methods(url):
    # CONNECT foi removido: é semântica de proxy HTTP, não um método de recurso;
    # via urllib.request sempre falha/gera ruído sem indicar nada sobre o alvo.
    dangerous = ['PUT', 'DELETE', 'TRACE', 'PATCH']
    findings = []
    for method in dangerous:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': SCAN_USER_AGENT}, method=method)
            resp = _SAFE_OPENER.open(req, timeout=TIMEOUT)
            if resp.getcode() in (200, 201, 204):
                findings.append(f"Método {method} permitido - risco de alteração/deleção")
        except urllib.error.HTTPError as e:
            if e.code not in (405, 501, 403, 404):
                findings.append(f"Método {method} retornou {e.code}")
        except Exception:
            pass
    return findings[:6]


# ============ PATH TRAVERSAL / LFI ============

LFI_PARAMS = ['file', 'path', 'page', 'include', 'doc', 'document', 'template', 'view', 'folder', 'dir', 'load', 'q']
LFI_PAYLOADS = [
    '../../../etc/passwd', '..%2F..%2F..%2Fetc/passwd', '....//....//....//etc/passwd',
    '..../..../..../etc/passwd', '%2e%2e%2f%2e%2e%2fetc/passwd', '..%252f..%252f..%252fetc/passwd',
    '../../../etc/passwd%00', '../../../etc/passwd\x00.jpg', '../../../etc/passwd%00.png',
    'php://filter/convert.base64-encode/resource=index',
    'php://filter/read=convert.base64-encode/resource=../../../etc/passwd',
    'php://filter/convert.base64-encode/resource=../config',
    '/etc/passwd', '..\\..\\..\\windows\\win.ini', '..%5c..%5c..%5cwindows%5cwin.ini',
]
LFI_INDICATORS = ['root:x:0:0', '[boot loader]', '/bin/bash', 'root:', '[extensions]', '[fonts]']
# Marcador de sucesso pro base64 do php://filter: se a resposta virar um blob
# base64 "limpo" e grande, é sinal forte de leitura de arquivo via wrapper.
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/=\s]{200,}$')

def _test_lfi(args):
    base_url, param, payload = args
    test_url = base_url + ('&' if '?' in base_url else '?') + param + '=' + urllib.parse.quote(payload)
    content, _, code = make_request(test_url)
    if content and code == 200:
        for ind in LFI_INDICATORS:
            if ind in content:
                return (param, f"Possível LFI/Path Traversal em ?{param}= - Conteúdo sensível exposto")
        if 'php://filter' in payload:
            stripped = content.strip()
            if len(stripped) > 200 and _BASE64_RE.match(stripped):
                return (param, f"Possível LFI via php://filter em ?{param}= - Resposta parece conteúdo base64 de arquivo lido")
    return None


def check_lfi(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + ('?' + parsed.query if parsed.query else '')
    tasks = [(base, p, payload) for p in LFI_PARAMS for payload in LFI_PAYLOADS]
    findings = []
    seen = set()
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(_test_lfi, tasks):
            if r and r[0] not in seen:
                seen.add(r[0])
                findings.append(r[1])
    return findings[:6]


# ============ COOKIE SECURITY ============

def check_cookie_security(url):
    """
    Avalia CADA Set-Cookie individualmente. resp.headers.get('Set-Cookie')
    só retorna o primeiro quando há múltiplos (comum: cookie de sessão +
    cookie de CSRF) - get_all evita ignorar o segundo cookie em diante.
    """
    findings = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': SCAN_USER_AGENT})
        with _SAFE_OPENER.open(req, timeout=TIMEOUT) as resp:
            try:
                all_cookies = resp.headers.get_all('Set-Cookie') or []
            except AttributeError:
                single = resp.headers.get('Set-Cookie')
                all_cookies = [single] if single else []
            for raw_cookie in all_cookies:
                name = raw_cookie.split('=', 1)[0].strip()
                lc = raw_cookie.lower()
                looks_like_session = any(
                    tag in name.lower() for tag in ('sess', 'auth', 'token', 'jwt', 'sid')
                )
                if 'httponly' not in lc:
                    sev_hint = ' (parece cookie de sessão)' if looks_like_session else ''
                    findings.append(f"Cookie '{name}' sem flag HttpOnly{sev_hint} - vulnerável a XSS roubando sessão")
                if 'secure' not in lc:
                    findings.append(f"Cookie '{name}' sem flag Secure - pode ser enviado via HTTP")
                if 'samesite' not in lc:
                    findings.append(f"Cookie '{name}' sem SameSite definido - risco de CSRF")
    except Exception:
        pass
    return findings


# ============ HTTPS REDIRECT ============

def check_https_redirect(url):
    parsed = urlparse(url)
    if _is_localhost(parsed):
        return []  # Em localhost não exige redirect HTTP→HTTPS
    host = parsed.netloc or parsed.path.split('/')[0]
    http_url = f"http://{host}/"
    try:
        req = urllib.request.Request(http_url, headers={'User-Agent': SCAN_USER_AGENT})
        resp = _SAFE_OPENER.open(req, timeout=TIMEOUT)
        final = resp.geturl() or ''
        if 'https' not in final:
            return ["Site HTTP não redireciona para HTTPS - tráfego pode ser interceptado"]
    except Exception:
        pass
    return []


# ============ CORS ============

def check_cors(url):
    """CORS permissivo: origem refletida/wildcard, e o combo pior-caso
    (ACAO=* ou refletido + Access-Control-Allow-Credentials=true, que
    permite roubo de sessão autenticada via JS de outro domínio)."""
    findings = []
    if _is_localhost(urlparse(url)):
        return findings

    probes = [
        ('https://evil.com', 'origem arbitrária'),
        ('null', 'origem null (iframe sandbox / file://)'),
    ]
    for origin, label in probes:
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': SCAN_USER_AGENT,
                'Origin': origin,
            })
            with _SAFE_OPENER.open(req, timeout=TIMEOUT) as resp:
                acao = (resp.headers.get('Access-Control-Allow-Origin') or '').strip()
                acac = (resp.headers.get('Access-Control-Allow-Credentials') or '').strip().lower()
                reflected = acao == '*' or (acao and origin.lower() in acao.lower())
                if reflected and acac == 'true':
                    findings.append(
                        f"CORS crítico: {label} refletida em ACAO='{acao[:50]}' "
                        f"COM Access-Control-Allow-Credentials=true - permite roubo de sessão via JS de outro domínio"
                    )
                elif reflected:
                    findings.append(f"CORS permissivo ({label}): Access-Control-Allow-Origin = {acao[:50]}")
        except Exception:
            pass
    return findings[:4]


# ============ INFO DISCLOSURE ============

def check_info_disclosure(url):
    findings = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': SCAN_USER_AGENT})
        with _SAFE_OPENER.open(req, timeout=TIMEOUT) as resp:
            h = resp.headers
            if 'Server' in h and h['Server']:
                findings.append(f"Header Server expõe tecnologia: {h['Server'][:60]}")
            if 'X-Powered-By' in h and h['X-Powered-By']:
                findings.append(f"X-Powered-By expõe: {h['X-Powered-By'][:60]}")
            if 'X-AspNet-Version' in h:
                findings.append("X-AspNet-Version expõe versão do ASP.NET")
            if 'X-Version' in h:
                findings.append(f"X-Version expõe: {h['X-Version'][:40]}")
            if 'X-Debug' in h or 'X-Debug-Token' in h:
                findings.append("Header de debug exposto")
    except Exception:
        pass
    return findings


# ============ SECURITY.TXT ============

def check_security_txt(url):
    findings = []
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in ['/.well-known/security.txt', '/security.txt']:
            full = urljoin(base, path)
            content, _, code = make_request(full)
            if content and code == 200 and len(content) > 20:
                if 'Contact:' not in content and 'contact' not in content.lower():
                    findings.append(f"security.txt encontrado em {path} mas sem campo Contact")
                return findings
    except Exception:
        pass
    return findings


# ============ MAIN ============

CHECK_FUNCS = {
    'misconfig': [
        ('Headers', check_security_headers),
        ('Paths', check_sensitive_paths),
        ('Dir Listing', check_directory_listing),
        ('Security.txt', check_security_txt),
    ],
    'sql': [('SQLi', check_sql_injection)],
    'xss': [('XSS', check_xss)],
    'redirect': [('Open Redirect', check_open_redirect)],
    'http_methods': [('HTTP Methods', check_http_methods)],
    'cors': [('CORS', check_cors)],
    'info': [('Info Disclosure', check_info_disclosure)],
    'lfi': [('Path Traversal', check_lfi)],
    'cookie': [('Cookies', check_cookie_security)],
    'https': [('HTTPS Redirect', check_https_redirect)],
}


def _preflight(url: str) -> str | None:
    """Confirma que o alvo responde antes de rodar as checagens. Sem isso, um
    alvo fora do ar/bloqueado por firewall gera silenciosamente 'nenhuma
    vulnerabilidade encontrada', o que é enganoso - é 'não verificado', não 'limpo'."""
    content, _, code = make_request(url)
    if code is None:
        return 'Alvo não respondeu (timeout, DNS ou conexão recusada) - resultados abaixo são inconclusivos'
    return None


def scan(url, checks=None, progress_cb=None, cancel_cb=None):
    if checks is None:
        checks = ['misconfig', 'sql', 'xss', 'redirect', 'http_methods', 'info']

    started = time.time()
    all_findings: list[dict] = []
    seen_ids: set[str] = set()
    print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Scan v{SCANNER_VERSION}: {url}{Colors.RESET}\n")

    preflight_error = _preflight(url)
    if preflight_error:
        print(f"{Colors.RED}[AVISO] {preflight_error}{Colors.RESET}")
        item = make_finding(
            'misconfig', 'INCONCLUSIVE', preflight_error,
            severity='info', confidence='high',
            remediation='Verifique se a URL está correta e acessível a partir deste servidor.',
        )
        all_findings.append(item)
        seen_ids.add(item['id'])
        return {
            'findings': all_findings,
            'meta': {
                'scanner_version': SCANNER_VERSION,
                'duration_ms': int((time.time() - started) * 1000),
                'checks_run': [],
                'findings_count': len(all_findings),
                'cancelled': False,
                'inconclusive': True,
            },
        }

    for check_name in checks:
        if cancel_cb and cancel_cb():
            break
        if (time.time() - started) > MAX_SCAN_SECONDS:
            item = make_finding(
                'misconfig', 'TIMEOUT',
                f'Orçamento de tempo do scan ({MAX_SCAN_SECONDS}s) esgotado - checagens restantes puladas',
                severity='info', confidence='high',
                remediation='Aumente SCANNER_MAX_SCAN_SECONDS ou reduza o número de checagens.',
            )
            if item['id'] not in seen_ids:
                seen_ids.add(item['id'])
                all_findings.append(item)
            break
        if check_name not in CHECK_FUNCS:
            continue
        for label, func in CHECK_FUNCS[check_name]:
            if cancel_cb and cancel_cb():
                break
            remaining = MAX_SCAN_SECONDS - (time.time() - started)
            if remaining <= 0:
                break
            if progress_cb:
                progress_cb(check_name, label, 'running')
            print(f"{Colors.YELLOW}[+] {label}...{Colors.RESET}", end=' ', flush=True)
            try:
                _exec = ThreadPoolExecutor(max_workers=1)
                fut = _exec.submit(func, url)
                try:
                    results = fut.result(timeout=remaining)
                    _exec.shutdown(wait=False)
                except FuturesTimeoutError:
                    _exec.shutdown(wait=False)  # não bloqueia esperando a thread travada terminar
                    raise TimeoutError(f'checagem "{label}" excedeu o tempo restante do scan ({remaining:.0f}s)')
                items = results if isinstance(results, list) else ([results] if results else [])
                category = check_name.upper().replace('_', ' ')
                for r in items:
                    item = make_finding(
                        check_name,
                        category,
                        str(r),
                        target_url=url,
                    )
                    if item['id'] in seen_ids:
                        continue
                    seen_ids.add(item['id'])
                    all_findings.append(item)
                if progress_cb:
                    progress_cb(check_name, label, 'done')
                print(f"{Colors.GREEN}OK{Colors.RESET}")
            except Exception as e:
                if progress_cb:
                    progress_cb(check_name, label, 'error')
                print(f"{Colors.RED}Erro{Colors.RESET}")
                item = make_finding(
                    check_name,
                    check_name.upper(),
                    f'Erro: {e}',
                    severity='low',
                    remediation='Verifique logs e conectividade com o alvo.',
                    confidence='low',
                )
                if item['id'] not in seen_ids:
                    seen_ids.add(item['id'])
                    all_findings.append(item)

    duration_ms = int((time.time() - started) * 1000)
    return {
        'findings': all_findings,
        'meta': {
            'scanner_version': SCANNER_VERSION,
            'duration_ms': duration_ms,
            'checks_run': list(checks),
            'findings_count': len(all_findings),
            'cancelled': bool(cancel_cb and cancel_cb()),
        },
    }


def main():
    parser = argparse.ArgumentParser(description='Scanner de vulnerabilidades web')
    parser.add_argument('url', help='URL alvo')
    parser.add_argument('-c', '--checks', nargs='+',
                        choices=list(CHECK_FUNCS.keys()),
                        default=['misconfig', 'sql', 'xss', 'redirect', 'info'],
                        help='Tipos de verificação')
    parser.add_argument(
        '--e2e-human',
        action='store_true',
        help='Executa um fluxo E2E com Playwright simulando comportamento humano (QA)',
    )
    args = parser.parse_args()
    url, err = validate_scan_target(args.url)
    if err:
        print(f"{Colors.RED}[ERRO] {err}{Colors.RESET}")
        return 2

    report = scan(url, args.checks)
    findings = report['findings']
    meta = report.get('meta', {})
    print(f"{Colors.BLUE}[*] Concluído em {meta.get('duration_ms', 0)} ms{Colors.RESET}")

    if args.e2e_human:
        try:
            run_e2e_human(url)
        except Exception as e:
            print(f"{Colors.RED}[E2E] Erro ao executar fluxo humanizado: {e}{Colors.RESET}")

    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  RELATÓRIO{Colors.RESET}\n")

    if not findings:
        print(f"{Colors.GREEN}[OK] Nenhuma vulnerabilidade aparente.{Colors.RESET}")
        return 0

    for item in findings:
        vuln_type = item.get('type', 'VULN')
        desc = item.get('desc', '')
        cwe = item.get('cwe', '')
        c = Colors.RED if any(x in vuln_type for x in ('SQL', 'XSS', 'LFI')) else Colors.YELLOW
        extra = f" ({cwe})" if cwe else ''
        print(f"{c}[{vuln_type}]{extra}{Colors.RESET} {desc}")
    print(f"\n{Colors.YELLOW}Total: {len(findings)}{Colors.RESET}")
    return 1


if __name__ == '__main__':
    sys.exit(main() or 0)


# ============ E2E HUMANIZADO COM PLAYWRIGHT (QA) ============

def _import_playwright():
    """
    Importa Playwright de forma preguiçosa para não quebrar o scanner
    caso a lib não esteja instalada no ambiente.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Playwright não está instalado. "
            "Instale com: pip install playwright && playwright install chromium"
        ) from exc
    return sync_playwright


def human_sleep(min_s: float = 0.3, max_s: float = 1.2) -> None:
    time.sleep(random.uniform(min_s, max_s))


def human_type(locator, text: str, min_delay: float = 0.05, max_delay: float = 0.18) -> None:
    for ch in text:
        locator.type(ch)
        time.sleep(random.uniform(min_delay, max_delay))


def human_mouse_move(page, x: float, y: float, steps: int = 20) -> None:
    try:
        current = page.mouse.position
    except Exception:
        current = {"x": 0, "y": 0}
    x0, y0 = current["x"], current["y"]
    for i in range(1, steps + 1):
        nx = x0 + (x - x0) * i / steps + random.uniform(-1, 1)
        ny = y0 + (y - y0) * i / steps + random.uniform(-1, 1)
        page.mouse.move(nx, ny)
        human_sleep(0.01, 0.05)


def human_scroll(page, total: int = 2000, step: int = 200) -> None:
    current = 0
    while current < total:
        page.mouse.wheel(0, step + random.randint(-30, 30))
        current += step
        human_sleep(0.3, 1.0)


def launch_human_browser():
    sync_playwright = _import_playwright()
    p = sync_playwright().start()

    browser = p.chromium.launch(
        headless=False,
        args=[
            "--start-maximized",
            "--disable-blink-features=AutomationControlled",
        ],
    )

    context = browser.new_context(
        viewport={"width": 1366, "height": 768},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        locale="pt-BR",
        timezone_id="America/Sao_Paulo",
    )

    context.add_init_script(
        "Object.defineProperty(navigator, 'languages', "
        "{get: () => ['pt-BR', 'pt', 'en-US', 'en']});"
    )

    page = context.new_page()
    return p, browser, context, page


def run_e2e_human(url: str) -> None:
    """
    Fluxo E2E genérico, simulando um usuário navegando na URL informada.
    Adapte este fluxo para o seu cenário real (login, cliques específicos, etc).
    """
    print(f"{Colors.BLUE}[E2E] Iniciando fluxo humanizado com Playwright em: {url}{Colors.RESET}")
    p, browser, context, page = launch_human_browser()
    try:
        page.goto(url, wait_until="domcontentloaded")
        human_sleep(1.5, 3.0)

        human_scroll(page, total=1200, step=200)

        # Exemplo: aguarda alguns segundos como se o usuário estivesse lendo
        human_sleep(2.0, 4.0)

        print(f"{Colors.GREEN}[E2E] Fluxo humanizado básico concluído. "
              f"Adapte a função run_e2e_human() para o seu caso.{Colors.RESET}")
    finally:
        browser.close()
        p.stop()
