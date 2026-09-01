"""
e2e_playwright.py: page.mouse.position não existe na API real do Playwright -
sem rastreamento manual, todo movimento Bézier "humano" partiria de (0,0)
(teleporte de canto = padrão robótico). Requer 'playwright install chromium';
se o browser não estiver instalado, os testes pulam com aviso claro em vez
de estourar erro.
"""
import pytest

pytest.importorskip("playwright.sync_api")


def _launch_or_skip(playwright):
    try:
        return playwright.chromium.launch(headless=True)
    except Exception as exc:
        pytest.skip(f"Chromium do Playwright não instalado - rode: python -m playwright install chromium ({exc})")


@pytest.fixture
def page():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = _launch_or_skip(p)
        pg = browser.new_page(viewport={"width": 1200, "height": 800})
        pg.set_content("<html><body>teste</body></html>")
        yield pg
        browser.close()


def test_posicao_inicial_e_o_centro_do_viewport_nao_zero_zero(page):
    import e2e_playwright as e2e
    pos = e2e._get_mouse_pos(page)
    assert pos == (600.0, 400.0)


def test_movimentos_consecutivos_encadeiam_posicao_real(page):
    import e2e_playwright as e2e
    e2e.mouse_move_bezier(page, 900, 300, steps=15)
    assert e2e._get_mouse_pos(page) == (900, 300)

    e2e.mouse_move_bezier(page, 100, 700, steps=15)
    assert e2e._get_mouse_pos(page) == (100, 700)


def test_posicao_e_limpa_ao_fechar_pagina():
    from playwright.sync_api import sync_playwright
    import e2e_playwright as e2e
    with sync_playwright() as p:
        browser = _launch_or_skip(p)
        pg = browser.new_page()
        pg.set_content("<html><body>x</body></html>")
        e2e.mouse_move_bezier(pg, 10, 10, steps=5)
        key = id(pg)
        assert key in e2e._LAST_MOUSE_POS
        pg.close()
        assert key not in e2e._LAST_MOUSE_POS
        browser.close()
