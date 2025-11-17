from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from config import Config
from models import db, User
import re

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
mail = Mail(app)

# Login Manager - управување со сесии
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
    if len(password) < 8:
        return False, "Password too short, must be more than 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    return True, "Password is valid"


def sanitize_input(user_input):
    """XSS """
    return user_input.strip().replace('<', '&lt;').replace('>', '&gt;')


def send_verification_email(user, code):
    msg = Message(
        subject="Email Verification Code",
        recipients=[user.email],
        body=f'''Hello {user.username},

Your verification code is: {code}

This code is valid for 10 minutes.

If you did not register, please ignore this email.
'''
    )
    mail.send(msg)


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

        if not username or not email or not password or not password_confirm:
            flash('All fields must be filled', 'danger')
            return redirect(url_for('register'))

        if not validate_email(email):
            flash('Invalid email address', 'danger')
            return redirect(url_for('register'))

        if password != password_confirm:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        new_user.is_email_verified = False

        code = new_user.generate_verification_code()

        db.session.add(new_user)
        db.session.commit()

        try:
            send_verification_email(new_user, code)
            flash('Registration successful! Check your email for verification code.', 'success')
        except Exception as e:
            flash(f'Error sending email: {str(e)}', 'danger')
            return redirect(url_for('register'))

        return redirect(url_for('verify_email', email=email))

    return render_template('register.html')


@app.route('/verify-email/<email>', methods=['GET', 'POST'])
def verify_email(email):
    """Верификација на email при регистрација (Fase 2)"""
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User does not exist', 'danger')
        return redirect(url_for('register'))

    if user.is_email_verified:
        flash('Email already verified', 'info')
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()

        if user.verify_code(code):
            user.is_email_verified = True
            user.email_verification_code = None
            db.session.commit()
            flash('Email successfully verified! You can now login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired code', 'danger')
            return redirect(url_for('verify_email', email=email))

    return render_template('verify_email.html', email=email)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Пријава (Fase 1 - проверка на username и лозинка)"""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        if not username or not password:
            flash('Enter username and password', 'warning')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Invalid username or password', 'warning')
            return redirect(url_for('login'))

        if not user.is_email_verified:
            flash('Email not verified. Check your email for verification code.', 'warning')
            return redirect(url_for('verify_email', email=user.email))

        # Генерирај верификаторски код за 2FA login
        code = user.generate_verification_code()
        db.session.commit()  # ВАЖНО: Сохрани го кодот во база!

        try:
            send_verification_email(user, code)
            flash('Verification code sent to your email!', 'success')
            return redirect(url_for('verify_login_code', user_id=user.id))
        except Exception as e:
            flash(f'Error sending verification code: {str(e)}', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/verify-login/<user_id>', methods=['GET', 'POST'])
def verify_login_code(user_id):
    """Верификација на код при login (Fase 2)"""
    user = User.query.get(user_id)

    if not user:
        flash('User does not exist', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()

        if user.verify_code(code):
            # Верификациониран - логирај го
            login_user(user, remember=True)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid or expired code', 'danger')
            return redirect(url_for('verify_login_code', user_id=user_id))

    return render_template('verify_login_code.html', email=user.email)


@app.route('/profile')
@login_required
def profile():
    """Профилна страна - заштитена"""
    return render_template('profile.html', user=current_user)


@app.route('/manage-login-info')
@login_required
def manage_login_info():
    """Управување со login информации - заштитена"""
    return render_template('manage_login_info.html', user=current_user)


@app.route('/logout')
@login_required
def logout():
    """Одјава"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, ssl_context='adhoc')
