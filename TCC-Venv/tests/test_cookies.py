"""check_cookie_security: avalia CADA Set-Cookie, não só o primeiro."""
import http.server
import scanner_site as s


class MultiCookieHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.send_header("Set-Cookie", "csrftoken=xyz; HttpOnly; Secure; SameSite=Strict")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_avalia_todos_os_cookies_nao_so_o_primeiro(http_server):
    base_url = http_server(MultiCookieHandler)
    findings = s.check_cookie_security(base_url)
    assert any("sessionid" in f for f in findings)
    assert not any("csrftoken" in f for f in findings), "csrftoken está seguro, não deveria aparecer"
