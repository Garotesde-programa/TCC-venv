"""check_sensitive_paths: baseline anti soft-404 e detecção real de exposição."""
import http.server
import scanner_site as s


class Soft404Handler(http.server.BaseHTTPRequestHandler):
    """Todo path devolve 200 com a mesma página, exceto /.env (exposição real)."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if self.path == "/.env":
            body = b"DB_PASSWORD=supersecreto123\nAPI_KEY=abc\n" * 3
        else:
            body = b"<html><body>Bem-vindo! Nada aqui.</body></html>" * 2
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Normal404Handler(http.server.BaseHTTPRequestHandler):
    """Servidor com 404 de verdade pra path inexistente."""
    def do_GET(self):
        if self.path == "/.env":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=supersecreto123\nAPI_KEY=abc\n" * 3)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, *a):
        pass


def test_ignora_soft_404(http_server):
    """Servidor que responde 200 pra qualquer path não deve gerar dezenas de
    falsos positivos - só a exposição real (/.env) deve aparecer."""
    base_url = http_server(Soft404Handler)
    findings = s.check_sensitive_paths(base_url)
    assert any(".env" in f for f in findings)
    assert len(findings) == 1, f"esperado só 1 achado (.env), veio: {findings}"


def test_detecta_exposicao_com_404_real(http_server):
    base_url = http_server(Normal404Handler)
    findings = s.check_sensitive_paths(base_url)
    assert any(".env" in f for f in findings)
    assert len(findings) == 1
