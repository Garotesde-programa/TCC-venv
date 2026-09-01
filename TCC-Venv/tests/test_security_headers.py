"""
check_security_headers: só acusa header ausente se faltar em HEAD e GET.
Mesma exceção deliberada de localhost do check_cors - contornada via
monkeypatch nos testes que validam a lógica de detecção.
"""
import http.server
import scanner_site as s


class OnlyOnGetHandler(http.server.BaseHTTPRequestHandler):
    """CSP só vem na resposta GET, não no HEAD - não deve gerar falso positivo."""
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=1")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=1")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class NoHeadersHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_nao_falso_positivo_quando_header_so_no_get(http_server, monkeypatch):
    monkeypatch.setattr(s, "_is_localhost", lambda *_: False)
    base_url = http_server(OnlyOnGetHandler)
    findings = s.check_security_headers(base_url)
    assert not any("Content-Security-Policy" in f for f in findings)


def test_detecta_headers_realmente_ausentes(http_server, monkeypatch):
    monkeypatch.setattr(s, "_is_localhost", lambda *_: False)
    base_url = http_server(NoHeadersHandler)
    findings = s.check_security_headers(base_url)
    assert any("X-Frame-Options" in f for f in findings)
    assert any("Content-Security-Policy" in f for f in findings)
