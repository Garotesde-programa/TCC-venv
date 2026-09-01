"""check_sql_injection: blind SQLi por tempo, medido de verdade (não apenas enviado)."""
import time
import http.server
import scanner_site as s


class SleepyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "sleep" in self.path.lower():
            time.sleep(5)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class FastHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_detecta_sqli_cega_por_tempo(http_server):
    base_url = http_server(SleepyHandler)
    r = s._test_sql_time((base_url.rstrip("/"), "id", "1' AND SLEEP(5)--", {"id": ["1"]}))
    assert r is not None
    assert r[0] == "id"


def test_nao_gera_falso_positivo_em_endpoint_rapido(http_server):
    base_url = http_server(FastHandler)
    r = s._test_sql_time((base_url.rstrip("/"), "id", "1' AND SLEEP(5)--", {"id": ["1"]}))
    assert r is None
