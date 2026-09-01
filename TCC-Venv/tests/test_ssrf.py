"""Validação de alvo (SSRF): host literal, DNS rebinding e esquemas não-HTTP."""
import socket
import scanner_site as s


def test_bloqueia_ip_privado_literal():
    norm, err = s.validate_scan_target("http://192.168.1.5/")
    assert norm is None
    assert "privada" in err.lower()


def test_permite_ip_publico():
    norm, err = s.validate_scan_target("http://93.184.216.34/")
    assert err is None
    assert norm == "http://93.184.216.34/"


def test_permite_loopback_por_padrao():
    """localhost é usado pra testar a própria interface - permitido por padrão
    (SCANNER_ALLOW_LOCALHOST=1)."""
    norm, err = s.validate_scan_target("http://127.0.0.1/")
    assert err is None


def test_bloqueia_dns_rebinding_para_rede_privada(monkeypatch):
    """
    Um domínio público pode resolver para um IP de rede privada (DNS rebinding).
    Simulamos isso com getaddrinfo mockado, sem depender de um domínio externo
    real (frágil/flaky) - só checando 127.0.0.1 não cobriria esse caso, já que
    loopback é permitido por padrão; aqui simulamos resolução para 10.0.0.5.
    """
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "dominio-malicioso-de-teste.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    norm, err = s.validate_scan_target("http://dominio-malicioso-de-teste.com/")
    assert norm is None
    assert "privada" in err.lower()


def test_bloqueia_dns_rebinding_para_loopback_quando_localhost_desabilitado(monkeypatch):
    """Se o admin desligar SCANNER_ALLOW_LOCALHOST, rebinding pra loopback via
    DNS também deve ser bloqueado - não só o IP literal."""
    monkeypatch.setattr(s, "ALLOW_LOCALHOST_TARGETS", False)
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "outro-dominio-malicioso.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    norm, err = s.validate_scan_target("http://outro-dominio-malicioso.com/")
    assert norm is None


def test_rejeita_esquema_ftp():
    norm, err = s.validate_scan_target("ftp://example.com/")
    assert norm is None
    assert "http" in err.lower()


def test_rejeita_esquema_file():
    norm, err = s.validate_scan_target("file:///etc/passwd")
    assert norm is None
    assert "http" in err.lower()


def test_rejeita_esquema_javascript():
    norm, err = s.validate_scan_target("javascript:alert(1)")
    assert norm is None
    assert "http" in err.lower()


def test_normaliza_url_sem_esquema():
    norm, err = s.validate_scan_target("example.com")
    assert err is None
    assert norm == "https://example.com/"


def test_normaliza_host_com_porta_sem_esquema():
    """'host:porta' não deve ser confundido com um esquema de URI."""
    norm, err = s.validate_scan_target("example.com:8080/path")
    assert err is None
    assert norm == "https://example.com:8080/path"
