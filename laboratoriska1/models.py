from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import uuid
import hashlib
import base64
import os
import random
from datetime import datetime, timedelta, timezone

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
        self.salt = base64.b16encode(os.urandom(16)).decode('utf-8')
        salted_password = (self.salt + password).encode('utf-8')
        self.password_hash = hashlib.sha256(salted_password).hexdigest()

    def check_password(self, password):
        salted_password = (self.salt + password).encode('utf-8')
        return self.password_hash == hashlib.sha256(salted_password).hexdigest()

    def generate_verification_code(self):
        """Генерирај 6-дигитен код"""
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        self.email_verification_code = code
        self.verification_code_expiry = datetime.now() + timedelta(minutes=10)
        return code

    def verify_code(self, code):
        """Провери дали кодот е валиден"""
        if not self.email_verification_code:
            return False

        if self.email_verification_code != code:
            return False

        if self.verification_code_expiry < datetime.now():
            return False

        return True

    def get_id(self):
        return self.id
