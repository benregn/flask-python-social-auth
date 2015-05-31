"""User models."""
import datetime as dt

from flask_login import UserMixin
from sqlalchemy.orm import relationship

from flask_social_auth.extensions import db, bcrypt


class Role(db.Model):

    """User roles."""

    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)  # pylint: disable=redefined-builtin,invalid-name
    name = db.Column(db.String(80), unique=True, nullable=False)
    user_id = db.Column(db.ForeignKey('users.id'), nullable=True)
    user = relationship('User', backref='roles')

    def __init__(self, name, **kwargs):
        """Init the role."""
        db.Model.__init__(self, name=name, **kwargs)

    def __repr__(self):
        """repr."""
        return '<Role({name})>'.format(name=self.name)


class User(UserMixin, db.Model):

    """The user model."""

    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # pylint: disable=redefined-builtin,invalid-name
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=True)  # the hashed password
    created_at = db.Column(db.DateTime, nullable=False, default=dt.datetime.utcnow)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    active = db.Column(db.Boolean(), default=False)

    def __init__(self, username, email, password=None, **kwargs):
        """Init the user name."""
        db.Model.__init__(self, username=username, email=email, **kwargs)
        if password:
            self.set_password(password)
        else:
            self.password = None

    @classmethod
    def get_by_id(cls, _id):
        """Get the user by ``_id``."""
        can_to_int = any(
            (isinstance(_id, str) and _id.isdigit(),
             isinstance(_id, (int, float))),
        )
        if can_to_int:
            return cls.query.get(int(_id))
        return None

    def set_password(self, password):
        """Set the password."""
        self.password = bcrypt.generate_password_hash(password)

    def check_password(self, value):
        """Validate the password."""
        return bcrypt.check_password_hash(self.password, value)

    @property
    def full_name(self):
        """Combine first_name and last_name."""
        return "{0} {1}".format(self.first_name, self.last_name)

    def __repr__(self):
        """repr."""
        return '<User({username!r})>'.format(username=self.username)
