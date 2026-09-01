"""
Fixtures compartilhadas da suite de testes do Scanner IA.
"""
import http.server
import socketserver
import threading
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Scripts"))

import pytest


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


@pytest.fixture
def http_server():
    """
    Sobe um http.server.HTTPServer descartável numa porta livre e devolve
    uma factory: start_server(handler_class) -> base_url.
    Usado pra simular alvos vulneráveis/seguros sem depender de rede externa.
    """
    servers = []

    def start(handler_class):
        srv = ReusableTCPServer(("127.0.0.1", 0), handler_class)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        servers.append(srv)
        return f"http://127.0.0.1:{port}/"

    yield start

    for srv in servers:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Cliente de teste do Flask (app_web.py) com DB temporário e sem rate limit padrão."""
    monkeypatch.setenv("SCANNER_DB_PATH", str(tmp_path / "test_scanner.db"))
    monkeypatch.setenv("SCANNER_RATE_LIMIT_MAX", "0")  # desliga rate limit por padrão
    import importlib
    import app_web
    importlib.reload(app_web)
    return app_web.app.test_client(), app_web
