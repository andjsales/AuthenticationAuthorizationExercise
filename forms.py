from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    email = StringField('Email', validators=[
                        InputRequired(), Length(max=50)])
    first_name = StringField('First Name', validators=[
                             InputRequired(), Length(max=30)])
    last_name = StringField('Last Name', validators=[
                            InputRequired(), Length(max=30)])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
                           InputRequired(), Length(max=20)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')  # Make sure this line is present


class FeedbackForm(FlaskForm):
    title = StringField("Title", validators=[Length(max=30)])
    content = StringField("Content", validators=[InputRequired()])
    submit = SubmitField('Submit')
