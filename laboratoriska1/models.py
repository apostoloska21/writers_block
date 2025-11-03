from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import uuid
import hashlib

db=SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__='app_users'

    id=db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    date_created = db.Column(db.DateTime, server_default=db.func.now())
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash=generate_password_hash(
            password,
            method='scrypt'
        )

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.id

#
#
# if __name__ == '__main__':
#     from flask import Flask
#
#     app=Flask(__name__)
#     app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
#     app.config['SECRET_KEY'] = 'test'
#     db.init_app(app)
#
#     with app.app_context():
#         db.create_all()
#
#         user = User(username="martina", email="martina@test.com")
#         user.set_password("TestnaLozinka123")
#
#         db.session.add(user)
#         db.session.commit()
#
#         fetched=User.query.filter_by(username="martina").first()
#         print("Hash:", fetched.password_hash)
#         print("Login success:", fetched.check_password("TestnaLozinka123"))
#         print("Login fail:", fetched.check_password("pogreshna"))