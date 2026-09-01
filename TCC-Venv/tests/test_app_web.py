"""app_web.py: autenticação por token, validação de cloudflare_timeout e rate limit."""
import inspect


def test_token_usa_comparacao_timing_safe(app_client):
    _, app_web = app_client
    assert "compare_digest" in inspect.getsource(app_web._check_web_token)
    assert "compare_digest" in inspect.getsource(app_web._check_internal_header)


def test_scan_rejeita_sem_token_quando_configurado(app_client, monkeypatch):
    client, app_web = app_client
    monkeypatch.setattr(app_web, "WEB_TOKEN", "segredo123")
    r = client.post("/scan", json={"url": "http://example.com", "authorized": True})
    assert r.status_code == 401


def test_scan_nao_quebra_com_cloudflare_timeout_invalido(app_client, monkeypatch):
    client, app_web = app_client
    monkeypatch.setattr(app_web, "WEB_TOKEN", "")
    r = client.post(
        "/scan",
        json={"url": "http://example.com", "authorized": True, "cloudflare_timeout": "abc"},
    )
    assert r.status_code == 400
    assert "cloudflare_timeout" in r.get_json().get("error", "")


def test_health_endpoint_ok(app_client):
    client, _ = app_client
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_rate_limit_bloqueia_apos_limite(app_client, monkeypatch):
    _, app_web = app_client
    monkeypatch.setattr(app_web, "RATE_LIMIT_MAX", 3)
    monkeypatch.setattr(app_web, "RATE_LIMIT_WINDOW", 60)
    monkeypatch.setattr(app_web, "_redis_client", None)
    app_web._RATE_LIMIT_BUCKETS.clear()

    with app_web.app.test_request_context("/", environ_base={"REMOTE_ADDR": "9.9.9.9"}):
        results = [app_web._rate_limit() for _ in range(5)]
    assert results == [True, True, True, False, False]
