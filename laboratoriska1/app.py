from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from config import Config
from models import db, User, Role, UserRole
from functools import wraps
from flask import abort
from datetime import datetime, timedelta
import re

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
mail = Mail(app)

# Login Manager - upravuvanje so sesii
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
    # XSS
    return user_input.strip().replace('<', '&lt;').replace('>', '&gt;')


def send_verification_email(user, code):
    msg = Message(
        subject="Email Verification Code",
        recipients=[user.email],
        body=f'''Hello {user.username},

Your verification code is: {code}

This code is valid for 10 minutes.
'''
    )
    mail.send(msg)


def send_expiration_notification(user, role_name, expired_at):
    """Send notification to user about expired role"""
    msg = Message(
        subject="Role Permission Expired - Writer's Block",
        recipients=[user.email],
        body=f'''Hello {user.username},

Your temporary {role_name} permission has expired.

Expiration time: {expired_at.strftime('%Y-%m-%d %H:%M:%S')}

You no longer have access to resources that require this role. If you need this permission again, please contact your administrator.

Best regards,
Writer's Block Team
'''
    )
    mail.send(msg)


def send_admin_expiration_notification(admin_user, expired_user, role_name, expired_at):
    """Send notification to admin about expired role"""
    msg = Message(
        subject="Temporary Role Expired - Writer's Block",
        recipients=[admin_user.email],
        body=f'''Hello {admin_user.username},

A temporary role you granted has expired.

User: {expired_user.username} ({expired_user.email})
Role: {role_name}
Expiration time: {expired_at.strftime('%Y-%m-%d %H:%M:%S')}

The user no longer has access to resources that require this role.

Best regards,
Writer's Block Team
'''
    )
    mail.send(msg)


def check_and_notify_expired_roles():
    """Check for expired DB_WRITER roles and send notifications"""
    now = datetime.now()
    db_writer_role = Role.query.filter_by(name='DB_WRITER').first()
    
    if not db_writer_role:
        return
    
    # Find expired DB_WRITER roles that haven't been notified
    expired_roles = UserRole.query.filter(
        UserRole.role_id == db_writer_role.id,
        UserRole.expires_at.isnot(None),
        UserRole.expires_at <= now,
        UserRole.expiration_notification_sent == False
    ).all()
    
    if not expired_roles:
        return
    
    # Get all admins
    org_admin_role = Role.query.filter_by(name='ORG_ADMIN').first()
    admins = []
    if org_admin_role:
        admin_user_roles = UserRole.query.filter_by(role_id=org_admin_role.id).all()
        admins = [ur.user for ur in admin_user_roles if ur.expires_at is None or ur.expires_at > now]
    
    for expired_role in expired_roles:
        user = expired_role.user
        
        # Send notification to the user (writer)
        try:
            send_expiration_notification(user, 'DB_WRITER', expired_role.expires_at)
        except Exception as e:
            print(f"Error sending expiration notification to {user.email}: {str(e)}")
        
        # Send notification to all admins
        for admin in admins:
            try:
                send_admin_expiration_notification(admin, user, 'DB_WRITER', expired_role.expires_at)
            except Exception as e:
                print(f"Error sending admin notification to {admin.email}: {str(e)}")
        
        # Mark as notified
        expired_role.expiration_notification_sent = True
    
    db.session.commit()


# Last time we checked for expired roles (throttle to avoid checking too frequently)
last_expiration_check = {'time': datetime.now()}

@app.before_request
def check_expired_roles_periodically():
    """Check for expired roles periodically (every 60 seconds)"""
    global last_expiration_check
    now = datetime.now()
    
    # Check every 60 seconds
    if (now - last_expiration_check['time']).total_seconds() >= 60:
        try:
            check_and_notify_expired_roles()
            last_expiration_check['time'] = now
        except Exception as e:
            print(f"Error checking expired roles: {str(e)}")


# funkcija za ogranicuvanje na pristap na ruti spored uloga
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if not current_user.has_role(role_name):
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

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

        # BOOTSTRAP: prviot user neka e ORG_ADMIN (za da moze da vlezes vo admin panel)
        if User.query.count() == 1:
            new_user.add_role('ORG_ADMIN')

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
    # verifikacija na meil pri registriranje
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

        code = user.generate_verification_code()
        db.session.commit()

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
    # verifikacija pri login
    user = User.query.get(user_id)

    if not user:
        flash('User does not exist', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()

        if user.verify_code(code):
            # ako korisnikot e verifikuvan togas da se logira
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

    return render_template('profile.html', user=current_user)


@app.route('/manage-login-info')
@login_required
def manage_login_info():
    return render_template('manage_login_info.html', user=current_user)

# ADMIN: list users + roles
@app.route('/admin/users')
@role_required('ORG_ADMIN')
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)


# ADMIN: grant org role (permanent)
@app.route('/admin/grant-org-employee/<user_id>')
@role_required('ORG_ADMIN')
def grant_org_employee(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    user.add_role('EMPLOYEE')
    flash('EMPLOYEE role granted.', 'success')
    return redirect(url_for('admin_users'))


# ADMIN: grant resource role JIT (temporary)
@app.route('/admin/grant-db-writer-jit/<user_id>')
@role_required('ORG_ADMIN')
def grant_db_writer_jit(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    user.add_role('DB_WRITER', hours=1)
    flash('Temporary DB_WRITER (1 hour) granted.', 'success')
    return redirect(url_for('admin_users'))


# Protected resources (examples)
@app.route('/org/dashboard')
@role_required('EMPLOYEE')
def org_dashboard():
    return render_template('org_dashboard.html')


@app.route('/db/write')
@role_required('DB_WRITER')
def db_write_action():
    return "DB WRITE: samo so DB_WRITER uloga."


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Seed roles (org + resource)
        base_roles = [
            ('ORG_ADMIN', 'org'),
            ('EMPLOYEE', 'org'),
            ('DB_READER', 'resource'),
            ('DB_WRITER', 'resource'),
        ]
        for name, scope in base_roles:
            if not Role.query.filter_by(name=name).first():
                db.session.add(Role(name=name, scope=scope))
        db.session.commit()

    app.run(debug=True)