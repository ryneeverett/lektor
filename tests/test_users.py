def test_insecure(webui):
    client = webui.test_client()

    assert client.get('/admin/').status_code == 200


def test_secure(webui_secure):
    client = webui_secure.test_client()

    assert client.get('/admin/').status_code == 401
