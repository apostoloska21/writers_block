from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import uuid
import hashlib
import base64
import os
import random
from datetime import datetime, timedelta

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'app_users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    salt = db.Column(db.String(32), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    date_created = db.Column(db.DateTime, server_default=db.func.now())
    is_active = db.Column(db.Boolean, default=True)

    is_email_verified = db.Column(db.Boolean, default=False)
    email_verification_code = db.Column(db.String(6))
    verification_code_expiry = db.Column(db.DateTime)

    def set_password(self, password):
        # salt e za da se zastitat lozinkite pred da se hasiraat i da nema ist hash ponataka
        self.salt = base64.b16encode(os.urandom(16)).decode('utf-8')
        salted_password = (self.salt + password).encode('utf-8')
        # so salt, ako 2 + users imaat ista lozinka, nema da imaat ist hash
        self.password_hash = hashlib.sha256(salted_password).hexdigest()

    # pri login, go zemam istiot salt, go spojuvam so novata lozinka hashiram i se sporeduva so zavucanieot salt,
    # ako se sovpadnat znaci userot postoi, login, ako ne greska
    def check_password(self, password):
        salted_password = (self.salt + password).encode('utf-8')
        return self.password_hash == hashlib.sha256(salted_password).hexdigest()

    def generate_verification_code(self):
        # generiranje na 6 biten kod
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        self.email_verification_code = code
        self.verification_code_expiry = datetime.now() + timedelta(minutes=10)
        return code

    def verify_code(self, code):
        # proverka dali kodot e validen
        if not self.email_verification_code:
            return False

        if self.email_verification_code != code:
            return False

        if self.verification_code_expiry < datetime.now():
            return False

        return True

    # RBAC check (includes JIT expiration)
    def has_role(self, role_name):
        now = datetime.now()
        for ur in self.user_roles:
            if ur.role.name == role_name and (ur.expires_at is None or ur.expires_at > now):
                return True
        return False

    # Assign role (hours=None => permanent; hours=1 => JIT 1h)
    def add_role(self, role_name, hours=None):
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return False

        expires = None
        if hours is not None:
            expires = datetime.now() + timedelta(hours=hours)

        ur = UserRole(user=self, role=role, expires_at=expires)
        db.session.add(ur)
        db.session.commit()
        return True

    def get_id(self):
        return self.id


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    # ORG_ADMIN, EMPLOYEE, DB_READER...
    name = db.Column(db.String(50), unique=True, nullable=False)
    # 'org' ili 'resource'
    scope = db.Column(db.String(20), nullable=False)


class UserRole(db.Model):
    __tablename__ = 'user_roles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('app_users.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    # None = permanent
    expires_at = db.Column(db.DateTime, nullable=True)
    # Track if expiration notification has been sent
    expiration_notification_sent = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User', backref=db.backref('user_roles', lazy='dynamic'))
    role = db.relationship('Role')
