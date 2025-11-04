from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, User
import re

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

# Upravuvanje na sesija dali user e najaven
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'You have to login first!'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    if len(password) < 5:
        return False, "password too short, must be more than 5 characters"
    if not any(c.isupper() for c in password):
        return False, "password must contain at least one upper letter"
    if not any(c.islower() for c in password):
        return False, "password must contain at least one lower letter"
    if not any(c.isdigit() for c in password):
        return False, "password must contain number"
    return True, "success"


# XSS zashtita
def sanitize_input(user_input):
    return user_input.strip().replace('<', '&lt;').replace('>', '&gt;')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')

        if not username or not email or not password:
            flash("all fields must be filled", 'failed registering')
            return redirect(url_for('register'))
        if not validate_email(email):
            flash("not valid email", 'failed registering')
            return redirect(url_for('register'))
        if password != password_confirm:
            flash("passwords do not match", 'failed registering')
            return redirect(url_for('register'))

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'not valid password')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('username already exists', 'failed registering')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("email already exists", 'failed registering')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("success registering, now you can login", "successful registration")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        if not username or not password:
            flash('enter username and password', 'warning')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('invalid username and password', 'warning')
            return redirect(url_for('login'))

        login_user(user, remember=True)
        flash(f'welcome, {user.username}!', 'successful login')
        return redirect(url_for('profile'))

    return render_template('login.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('user is logged out', 'successfully logged out')
    return redirect(url_for('index'))


@app.route('/manage-login-info')
@login_required
def manage_login_info():
    return render_template('manage_login_info.html', user=current_user)


if __name__ == '__main__':
    # with app.app_context():
    #     db.create_all()
    app.run(debug=True, ssl_context='adhoc')
