"""
check_cors: origem arbitrária, null origin e combo credentials=true.

A função pula alvos localhost de propósito (evita o scanner acusar CORS na
própria interface). Como o http_server de teste só pode escutar em
127.0.0.1, forçamos _is_localhost=False via monkeypatch pra testar a lógica
de detecção em si, e não essa exceção deliberada.
"""
import http.server
import scanner_site as s


class PermissiveCredCorsHandler(http.server.BaseHTTPRequestHandler):
    """Reflete a Origin recebida E manda credentials=true - pior caso."""
    def do_GET(self):
        origin = self.headers.get("Origin", "*")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class SafeCorsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_detecta_cors_critico_com_credentials(http_server, monkeypatch):
    monkeypatch.setattr(s, "_is_localhost", lambda *_: False)
    base_url = http_server(PermissiveCredCorsHandler)
    findings = s.check_cors(base_url)
    assert any("crítico" in f.lower() for f in findings)


def test_sem_falso_positivo_sem_cors(http_server, monkeypatch):
    monkeypatch.setattr(s, "_is_localhost", lambda *_: False)
    base_url = http_server(SafeCorsHandler)
    findings = s.check_cors(base_url)
    assert findings == []


def test_pula_verificacao_na_propria_interface(http_server):
    """Comportamento intencional: NÃO monkeypatchado - contra a própria UI
    (127.0.0.1), check_cors deve pular e não reportar nada."""
    base_url = http_server(PermissiveCredCorsHandler)
    findings = s.check_cors(base_url)
    assert findings == []
