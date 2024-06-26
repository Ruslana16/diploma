from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, SelectField, RadioField, EmailField, TextAreaField, BooleanField, HiddenField, FieldList, FormField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Optional, ValidationError
from flask import flash
import re


class RegistrationForm(FlaskForm):
    username = StringField('Lietotājvārds', [
        DataRequired(message='Lietotājvārds ir obligāts'),
        Length(min=4, max=15, message='Lietotājvārdam jābūt no 4 līdz 15 simboliem garam')
    ])
    password = PasswordField('Parole', [
        DataRequired(message='Parole ir obligāta'),
        Length(min=8, message='Parolei jābūt vismaz 8 simboliem garai'),
        EqualTo('confirm_password', message='Parolēm jāsakrīt'),
    ])
    confirm_password = PasswordField('Apstiprināt paroli')
    recaptcha = RecaptchaField()
    role = HiddenField('Loma')

    email = StringField('E-pasts', [
        Optional(),
        Email(message='Lūdzu, ievadiet derīgu e-pasta adresi')
    ])

    def validate_password(form, field):
        password = field.data
        if not re.search(r'[A-Z]', password):
            flash('Parolei jābūt vismaz vienam lielajam burtam.', 'danger')
            raise ValidationError('Parolei jābūt vismaz vienam lielajam burtam.')
        if not re.search(r'\d', password):
            flash('Parolei jābūt vismaz vienam ciparam.', 'danger')
            raise ValidationError('Parolei jābūt vismaz vienam ciparam.')
        if not re.search(r'[\W]', password):  # Non-word character (symbol)
            flash('Parolei jābūt vismaz vienam simbolam.', 'danger')
            raise ValidationError('Parolei jābūt vismaz vienam simbolam.')

class VotingOptionForm(FlaskForm):
    id = HiddenField('id')
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

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

class AuditLogForm(FlaskForm):
    search = StringField('Search Logs', validators=[DataRequired()])
    submit = SubmitField('Search')









            


