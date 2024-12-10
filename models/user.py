from flask_login import UserMixin
from datetime import datetime
import logging

from app import db

class User(UserMixin, db.Model):

    id = db.Column(db.String(100), primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    first_login = db.Column(db.DateTime(timezone=True))
    last_login = db.Column(db.DateTime(timezone=True))
    login_count = db.Column(db.Integer)
    idp_token = db.Column(db.String(1000))
    
    def __init__(self, id, name, email, idp_token):
        self.id = id
        self.name = name
        self.email = email        
        self.idp_token = idp_token
    
    def __str__(self): 
        return f"user: id[{self.id}], name[{self.name}], email[{self.email}]"

    def claims(self):
        """Use this method to render all assigned claims on profile page."""
        return {'name': self.name,
                'email': self.email}.items()

    def initial_login(self):
        logging.info(f"User.initial_login: {self}")
    
        self.first_login = datetime.now()
        self.last_login = self.first_login
        self.login_count = 1

        db.session.add(self)
        db.session.commit()

    def update_login(self):         
        logging.info(f"User.update_login: {self}")
    
        self.last_login = datetime.now()
        self.login_count += 1

        db.session.commit()   
            
    @staticmethod
    def get(user_id):
        user = User.query.get(user_id)
        return user