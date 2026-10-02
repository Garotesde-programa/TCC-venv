"""
Testes do agente de IA (ai_agent.py). Não dependem de um Ollama real
rodando: _ollama_chat é mockado pra simular as respostas do modelo.
"""
from unittest.mock import patch

import ai_agent


def test_is_enabled_reflete_env(monkeypatch):
    monkeypatch.setattr(ai_agent, "AI_BACKEND", "off")
    assert ai_agent.is_enabled() is False

    monkeypatch.setattr(ai_agent, "AI_BACKEND", "ollama")
    assert ai_agent.is_enabled() is True


def test_agent_scan_cai_pro_padrao_quando_ollama_indisponivel(http_server, monkeypatch):
    """Sem Ollama de pé, agent_scan deve completar o scan normalmente
    (mesmo resultado do scan() padrão) e registrar o motivo no agent_log."""

    class OkHandler:
        pass

    import http.server as hs

    class Handler(hs.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def log_message(self, *a):
            pass

    url = http_server(Handler)

    monkeypatch.setattr(ai_agent, "AI_BACKEND", "ollama")
    monkeypatch.setattr(ai_agent, "is_available", lambda timeout=3: False)

    result = ai_agent.agent_scan(url, checks=["misconfig"])

    assert "findings" in result
    assert "agent_log" in result
    assert any("indisponível" in msg for msg in result["agent_log"])


def test_agent_scan_executa_tool_call_escolhido_pelo_modelo(http_server, monkeypatch):
    """Simula o modelo escolhendo 'check_security_headers' e depois
    decidindo parar (sem mais tool_calls)."""
    import http.server as hs

    class Handler(hs.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def log_message(self, *a):
            pass

    url = http_server(Handler)

    monkeypatch.setattr(ai_agent, "AI_BACKEND", "ollama")
    monkeypatch.setattr(ai_agent, "is_available", lambda timeout=3: True)

    responses = [
        {
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {"function": {"name": "check_security_headers", "arguments": {"url": url}}}
                ],
            }
        },
        {
            "message": {
                "role": "assistant",
                "content": "Achados suficientes por agora, parando.",
            }
        },
    ]

    with patch.object(ai_agent, "_ollama_chat", side_effect=responses):
        result = ai_agent.agent_scan(url, checks=["misconfig"])

    # 'checks_run' guarda ids de findings (mesmo formato de scan()), não
    # nomes de função - a prova de que o check certo rodou é no agent_log
    # e no fato de termos pelo menos um finding normalizado (com 'id').
    assert any("check_security_headers" in msg for msg in result["agent_log"])
    assert result["findings"], "esperava ao menos um finding normalizado"
    assert all("id" in f and "severity" in f for f in result["findings"])
    assert any("parando" in msg or "decidiu parar" in msg for msg in result["agent_log"])


def test_enrich_insights_mantem_score_e_so_adiciona_narrativa(monkeypatch):
    base_insights = {"risk_score": 42, "risk_level": "medio", "priority": []}

    monkeypatch.setattr(ai_agent, "is_available", lambda timeout=3: True)
    fake_response = {"message": {"content": "Resumo gerado pelo modelo local."}}

    with patch.object(ai_agent, "_ollama_chat", return_value=fake_response):
        enriched = ai_agent.enrich_insights("http://alvo.teste/", [], base_insights)

    assert enriched["risk_score"] == 42
    assert enriched["risk_level"] == "medio"
    assert enriched["narrative_llm"] == "Resumo gerado pelo modelo local."


def test_enrich_insights_sem_ollama_nao_altera_nada(monkeypatch):
    base_insights = {"risk_score": 10, "risk_level": "baixo", "priority": []}
    monkeypatch.setattr(ai_agent, "is_available", lambda timeout=3: False)

    result = ai_agent.enrich_insights("http://alvo.teste/", [], base_insights)

    assert result is base_insights
    assert "narrative_llm" not in result
