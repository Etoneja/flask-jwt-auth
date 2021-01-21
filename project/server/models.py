# project/server/models.py

from datetime import datetime, timedelta

import jwt

from project.server import app, db, bcrypt


class User(db.Model):
    """User Model for storing user related details"""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, password, admin=False):
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get("BCRYPT_LOG_ROUNDS")
        ).decode()
        self.registered_on = datetime.now()
        self.admin = admin

    @staticmethod
    def encode_auth_token(user_id):
        """
        Generates the Auth token
        :return: string
        """
        try:
            payload = {
                "exp": datetime.utcnow() + timedelta(days=0, seconds=5),
                "iat": datetime.utcnow(),
                "sub": user_id
            }
            auth_token = jwt.encode(
                payload,
                app.config.get("SECRET_KEY"),
                "HS256"
            )
            return auth_token
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(
                auth_token,
                app.config.get("SECRET_KEY"),
                "HS256"
            )
            return payload["sub"]
        except jwt.ExpiredSignatureError:
            return "Signature expired. Please log in again."
        except jwt.InvalidTokenError:
            return "Invalid token. Please log in again."


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.now()

    def __repr__(self):
        return f"<id: token: {self.token}>"
