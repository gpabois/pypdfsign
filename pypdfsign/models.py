from flask_sqlalchemy import SQLAlchemy

import bcrypt

db = SQLAlchemy()

class users(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    
    def __init__(email, password):
        self.email = email
        self.password = bcrypt.hashpw(password, bcrypt.gensalt( 12 ))
    
    def check_password(self, password):
        return bcrypt.checkpw(self.password, password)
        
class files(db.Model):
    id          = db.Column('id', db.Integer, primary_key = True)
    file_id     = db.Column(db.Text)
    store_id    = db.Column(db.Text)
    store_path  = db.Column(db.Text)
    
    def __init__(self, file_id, store_id, store_path):
        self.file_id = file_id
        self.store_id = store_id
        self.store_path = store_path        

class certs_pks(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('users', backref=db.backref('certs_pks', lazy=True))   
    
    cert_fid = db.Column(db.Text)
    pk_fid = db.Column(db.Text)
    pin_code = db.Column(db.Text)
    
    def __init__(self, user_id, cert_fid, pk_fid, pin_code):
        self.user_id = user_id
        self.cert_fid = cert_fid
        self.pk_fid = pk_fid
        self.pin_code = bcrypt.hashpw(password, bcrypt.gensalt(12))
    
    def check_pin_code(cert_pk, pin_code):
        return bcrypt.checkpw(self.cert_pk, pin_code)