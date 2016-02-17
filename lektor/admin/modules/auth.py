import flask
from flask import Blueprint, g, redirect, url_for

from lektor.project import Project


bp = Blueprint('auth', __name__)

project = Project.discover()

if getattr(project, 'database_uri', False):
    @bp.record_once
    def init(state):
        from flask.ext import login
        from flask.ext.login import login_user, logout_user

        app = state.app

        with app.app_context():
            from lektor.admin.models import User

        app.config['SQLALCHEMY_DATABASE_URI'] = project.database_uri
        app.config['SECRET_KEY'] = project.secret_key

        login_manager = login.LoginManager()
        login_manager.init_app(app)

        @login_manager.user_loader
        def load_user(user_id):
            return User.get(id=user_id)

        from flask.ext.wtf import Form
        from wtforms import StringField, PasswordField, SubmitField

        class LoginForm(Form):
            username = StringField('username')
            password = PasswordField('password')
            submit = SubmitField('login')

            def validate(self):
                user = User.get(username=self.username.data)
                return user and user.check_password(self.password.data)

        class NewUserForm(Form):
            username = StringField('username')
            submit = SubmitField('submit')

        @app.before_request
        def require_authorization():
            from flask import request
            from flask.ext.login import current_user

            if not (current_user.is_authenticated or
                    request.endpoint in ['login', 'set_password']):
                return login_manager.unauthorized()

        @app.route('/login', methods=['GET', 'POST'])
        def login():
            form = LoginForm()
            if form.validate_on_submit():
                logged_in = login_user(User.get(username=form.username.data))
                return (redirect(g.admin_context.admin_root)
                        if logged_in else redirect(url_for('login')))
            return flask.render_template('login.html', form=form)

        @app.route('/logout')
        def logout():
            logout_user()
            return redirect(g.admin_context.admin_root)

        @app.route('/add-user', methods=['GET', 'POST'])
        def add_user():
            from flask.ext.login import current_user

            if current_user.id != 1:
                return login_manager.unauthorized()

            form = NewUserForm()
            if form.validate_on_submit():
                user = User(form.username.data)
                tmp_token = user.make_tmp_token()
                user.save()
                return redirect(url_for(
                    'set_password_link',
                    username=user.username, tmp_token=tmp_token))
            return flask.render_template('add_user.html', form=form)

        @app.route('/set_password_link/<username>/<tmp_token>')
        def set_password_link(username, tmp_token):
            link = url_for('set_password', tmp_token=tmp_token, _external=True)
            return flask.render_template(
                'set_password_link.html', link=link, username=username)

        @app.route('/set_password/<tmp_token>', methods=['GET', 'POST'])
        def set_password(tmp_token):
            user = User.get(tmp_token=tmp_token)

            if not user or user.pw_hash:
                return login_manager.unauthorized()

            form = LoginForm(username=user.username)
            if form.is_submitted() and form.username.data == user.username:
                user.set_password(form.password.data)
                user.save()
                return redirect(url_for('login'))
            return flask.render_template('login.html', form=form)
