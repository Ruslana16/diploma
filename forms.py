from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, RadioField, EmailField, TextAreaField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Optional, ValidationError#
from models import User
from wtforms import StringField, TextAreaField, FieldList, FormField, SubmitField
from flask_wtf import RecaptchaField

class RegistrationForm(FlaskForm):
    username = StringField('Username', [
        DataRequired(),
        Length(min=4, max=15)
    ])
    password = PasswordField('Password', [
        DataRequired(),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    recaptcha = RecaptchaField()
    role = HiddenField('Role') 
    confirm_password = PasswordField('Confirm Password')
    
    # Email field is optional and added only if the role is creator
    email = StringField('Email', [
        Optional(),
        Email()
    ])

    submit = SubmitField('Sign Up')

            
class VotingOptionForm(FlaskForm):
    option_text = StringField('Option', validators=[DataRequired()])

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired(), Length(min=5, max=200)])
    parent_id = HiddenField('Parent ID')
    submit = SubmitField('Post Comment')

class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    bio = TextAreaField('Biography')
    avatar = StringField('Avatar URL')
    submit = SubmitField('Update')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=1000)])
    submit = SubmitField('Send Message')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')



class IdeaForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('Politika', 'Politika'),
        ('Vide', 'Vide'),
        ('Sabiedrības veselība', 'Sabiedrības veselība'),
        ('Izglītība', 'Izglītība'),
        ('Māksla', 'Māksla'),
        ('Izklaide', 'Izklaide'),
        ('Transports', 'Transports'),
        ('Pilsētplānošana', 'Pilsētplānošana'),
        ('Sabiedrības drošība', 'Sabiedrības drošība'),
        ('Ekonomiskā attīstība', 'Ekonomiskā attīstība'),
        ('Atpūta', 'Atpūta')

    ], validators=[DataRequired()])
    voting_options = FieldList(FormField(VotingOptionForm), min_entries=1, max_entries=5)
    submit = SubmitField('Submit Idea')


class DeleteIdeaForm(FlaskForm):
    submit = SubmitField('Delete')

class LikeForm(FlaskForm):
    idea_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField('Like')

class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')








            


