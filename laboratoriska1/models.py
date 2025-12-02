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

    def get_id(self):
        return self.id
