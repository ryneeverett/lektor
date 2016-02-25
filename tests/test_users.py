import json


def test_insecure(webui):
    app = webui.test_client()

    assert app.get('/admin/').status_code == 200


def test_secure(webui_secure):
    app = webui_secure.test_client()

    def login(username, password):
        return app.post(
            '/users/login', data={'username': username, 'password': password})

    def is_admin():
        return json.loads(app.get('/users/is_admin').data)['is_admin']

    # Unauthenticated
    assert app.get('/admin/').status_code == 401

    # Admin
    assert login('admin', 'admin').status_code == 302

    assert app.get('/admin/').status_code == 200

    assert app.get('/users/').status_code == 200

    assert is_admin() is True

    user = app.post(
        '/users/add',
        data=json.dumps({'username': 'user'}), content_type='application/json')
    set_password = json.loads(user.data)['link']

    app.get('/users/logout')
    assert app.get('/admin/').status_code == 401

    # User
    app.post(set_password, data={'username': 'user', 'password': 'user'})
    assert login('user', 'user').status_code == 302

    assert app.get('/admin/').status_code == 200

    assert app.get('/users/').status_code == 401

    assert is_admin() is False
