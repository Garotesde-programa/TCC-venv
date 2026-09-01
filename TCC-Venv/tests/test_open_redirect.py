"""check_open_redirect: detecção real via NoRedirectHandler + variantes de payload."""
from urllib.parse import urlparse, parse_qs
import http.server
import scanner_site as s


class RedirectingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        target = q.get("next", [""])[0]
        if target:
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class SafeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_detecta_open_redirect(http_server):
    base_url = http_server(RedirectingHandler)
    findings = s.check_open_redirect(base_url.rstrip("/") + "/")
    assert len(findings) >= 1
    assert any("evil.com" in f.lower() for f in findings)


def test_sem_falso_positivo_sem_redirect(http_server):
    base_url = http_server(SafeHandler)
    findings = s.check_open_redirect(base_url.rstrip("/") + "/")
    assert findings == []
