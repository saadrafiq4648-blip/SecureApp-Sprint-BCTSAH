from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=False)
    recipient_email = db.Column(db.String(120), nullable=False)
    permission = db.Column(db.String(20), default="read")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    active_account = db.Column(db.Boolean, default=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    original_name = db.Column(db.String(256), nullable=False)
    path = db.Column(db.String(512), nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    shares = db.relationship("Share", backref="file", lazy=True)

    def shared_with(self, user, action="read"):
        if self.is_public and action == "read":
            return True
        return any(s.recipient_email == user.email for s in self.shares)
