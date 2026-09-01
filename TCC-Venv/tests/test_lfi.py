"""_test_lfi: path traversal clássico e php://filter (base64)."""
import base64
import http.server
from urllib.parse import urlparse, parse_qs, unquote
import scanner_site as s


class LfiHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        file_param = unquote(q.get("file", [""])[0])
        self.send_response(200)
        self.end_headers()
        if "etc/passwd" in file_param:
            self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\n")
        elif "php://filter" in file_param:
            self.wfile.write(base64.b64encode(b"<?php $secret = 'abc123'; ?>" * 10))
        else:
            self.wfile.write(b"conteudo normal")

    def log_message(self, *a):
        pass


def test_detecta_path_traversal_classico(http_server):
    base_url = http_server(LfiHandler)
    r = s._test_lfi((base_url.rstrip("/"), "file", "../../../etc/passwd"))
    assert r is not None
    assert r[0] == "file"


def test_detecta_php_filter_base64(http_server):
    base_url = http_server(LfiHandler)
    r = s._test_lfi((base_url.rstrip("/"), "file", "php://filter/convert.base64-encode/resource=../config"))
    assert r is not None


def test_sem_falso_positivo_conteudo_normal(http_server):
    base_url = http_server(LfiHandler)
    r = s._test_lfi((base_url.rstrip("/"), "file", "arquivo_normal.txt"))
    assert r is None
