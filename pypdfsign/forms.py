from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length, Email

class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    
    def validate(self):
        initial_validation = super(LoginForm, self).validate()
        if not initial_validation:
            return False
        users.query.filter_by(email=self.email.data).first()
    
        if not user or not user.check_password(self.password.data):
            self.email.errors.append('Email ou mot de passe invalide')
            return False
    
        self.user = user
        return True

class RegisterUserForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired(), Length(min=4), EqualTo('confirm_password')])
    confirm_password = PasswordField('confirm_password', validators=[Length(min=4)])

class CreateCertForm(FlaskForm):
    common_name = StringField('common_name', validators=[DataRequired()])
    pin_code = PasswordField ('pin_code', validators=[
        DataRequired(), 
        Length(min=4, max=4), 
        EqualTo('pin_code_confirm', message="Both pin codes must match")
    ])
    confirm_pin_code = PasswordField('confirm_pin_code', Length(min=4, max=4))