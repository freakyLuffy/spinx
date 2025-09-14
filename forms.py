from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', 
                             validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired()])
    password = PasswordField('Password', 
                             validators=[DataRequired()])
    submit = SubmitField('Login')

# Add this new form class to your existing forms.py
class AddAccountForm(FlaskForm):
    phone = StringField('Phone Number (with country code)', validators=[DataRequired()])
    api_id = StringField('API ID', validators=[DataRequired()])
    api_hash = StringField('API Hash', validators=[DataRequired()])
    submit = SubmitField('Add Account')