import os
import ssl
import urllib.request
import json
import certifi
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from extensions import db, mail, login_manager, bcrypt, migrate
from forms import RegistrationForm, CommentForm, LikeForm, VotingOptionForm, LoginForm, ContactForm, IdeaForm, UpdateProfileForm, ChangePasswordForm
from models import User, Idea, Comment, Like, VotingOption, Vote
from utils import generate_confirmation_token, confirm_token
from emails import send_email
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from wtforms.validators import DataRequired, Email, Optional
from dotenv import load_dotenv, find_dotenv

# Load environment variables from .env file
load_dotenv()

dotenv_path = find_dotenv()
load_dotenv(dotenv_path)

# Debug function to print environment variables
def print_env_variables():
    print(f"SECRET_KEY: {os.getenv('SECRET_KEY')}")
    print(f"SECURITY_PASSWORD_SALT: {os.getenv('SECURITY_PASSWORD_SALT')}")
    print(f"DATABASE_URL: {os.getenv('DATABASE_URL')}")
    print(f"MAIL_USERNAME: {os.getenv('MAIL_USERNAME')}")
    print(f"MAIL_PASSWORD: {os.getenv('MAIL_PASSWORD')}")
    print(f"MAIL_DEFAULT_SENDER: {os.getenv('MAIL_DEFAULT_SENDER')}")
    print(f"FLASK_ENV: {os.getenv('FLASK_ENV')}")
    print(f"FLASK_DEBUG: {os.getenv('FLASK_DEBUG')}")
    print(f"RECAPTCHA_PRIVATE_KEY: {os.getenv('RECAPTCHA_PRIVATE_KEY')}")
    print(f"RECAPTCHA_PUBLIC_KEY: {os.getenv('RECAPTCHA_PUBLIC_KEY')}")

# Call the debug function
print_env_variables()

class VerifiedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self):
        context = ssl.create_default_context(cafile=certifi.where())
        super().__init__(context=context)

opener = urllib.request.build_opener(VerifiedHTTPSHandler())
urllib.request.install_opener(opener)

def verify_recaptcha(response_token):
    recaptcha_secret = os.getenv('RECAPTCHA_PRIVATE_KEY')
    if not recaptcha_secret:
        print("RECAPTCHA_PRIVATE_KEY is not set in environment variables.")
        return False
    print(f"Using reCAPTCHA secret: {recaptcha_secret}")  # Debug statement
    url = f"https://www.google.com/recaptcha/api/siteverify?secret={recaptcha_secret}&response={response_token}"

    try:
        response = urllib.request.urlopen(url)
        result = json.load(response)
        print("reCAPTCHA verification result:", result)  # Debug statement
        return result.get('success', False)
    except urllib.error.URLError as e:
        print(f"Error verifying reCAPTCHA: {e}")
        return False

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'hbcirebvyrebgvugbenvu')

    csrf = CSRFProtect(app)

    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)  

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def inject_user():
        return dict(current_user=current_user)

    register_routes(app)

    return app

def register_routes(app):
    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            try:
                user = User.query.filter_by(username=form.username.data).first()
                if user:
                    print(f'User found: {user.username}')
                if user and bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    flash('Login successful.', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Login unsuccessful. Please check your username and password.', 'danger')
            except Exception as e:
                flash('An error occurred during login. Please try again.', 'danger')
                print(f'Error during login: {e}')
        else:
            print("Form validation failed:", form.errors)  # Debug statement
            print("Form data:", form.data)  # Additional debug statement
        return render_template('login.html', title='Login', form=form)



    @app.route('/logout')
    def logout():
        logout_user()
        flash('Jūs esat izrakstījies.', 'info')
        return redirect(url_for('home'))

    @app.route('/registration', methods=['GET', 'POST'])
    def registration():
        role = request.args.get('role', 'observer')
        form = RegistrationForm(role=role)

        recaptcha_public_key = os.getenv('RECAPTCHA_PUBLIC_KEY')

        if form.validate_on_submit():
            recaptcha_response = request.form.get('g-recaptcha-response')
            print(f"reCAPTCHA response: {recaptcha_response}")  # Debug statement
            if verify_recaptcha(recaptcha_response):
                email = form.email.data if role == 'creator' else None

                # Check for existing username
                existing_user = User.query.filter_by(username=form.username.data).first()
                if existing_user:
                    flash('Lietotājvārds jau eksistē. Lūdzu, izvēlieties citu.', 'danger')
                    return render_template('registration.html', title='Reģistrēties', form=form, role=role, recaptcha_public_key=recaptcha_public_key)

                # Check for existing email (if email is required)
                if email:
                    existing_email = User.query.filter_by(email=email).first()
                    if existing_email:
                        flash('E-pasta adrese jau eksistē. Lūdzu, izvēlieties citu.', 'danger')
                        return render_template('registration.html', title='Reģistrēties', form=form, role=role, recaptcha_public_key=recaptcha_public_key)

                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user = User(username=form.username.data, email=email, password=hashed_password, role=role, confirmed=False)
                db.session.add(user)
                db.session.commit()

                login_user(user)
                print("Lietotājs pieslēdzies:", user.username)  # Debug statement

                if user.email:
                    token = generate_confirmation_token(user.email)
                    confirm_url = url_for('confirm_email', token=token, _external=True)
                    html = render_template('activate.html', confirm_url=confirm_url)
                    send_email(user.email, 'Lūdzu, apstipriniet savu e-pastu', html)

                flash('Paldies, ka reģistrējāties! Lūdzu, pārbaudiet savu e-pastu, lai saņemtu apstiprinājuma saiti.', 'success')
                return redirect(url_for('dashboard'))  # Redirect to the dashboard after registration
            else:
                flash('Lūdzu, aizpildiet reCAPTCHA.', 'danger')
        else:
            print("Formas validācija neizdevās:", form.errors)  # Debug statement
            print("Formas dati:", form.data)  # Additional debug statement

        return render_template('registration.html', title='Reģistrēties', form=form, role=role, recaptcha_public_key=recaptcha_public_key)




    @app.route('/dashboard')
    @login_required
    def dashboard():
        user_ideas = Idea.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', ideas=user_ideas)

    @app.route('/confirm/<token>')
    def confirm_email(token):
        try:
            email = confirm_token(token)
        except:
            flash('Apstiprinājuma saite ir nederīga vai tā ir beidzies.', 'danger')
            return redirect(url_for('home'))

        user = User.query.filter_by(email=email).first_or_404()
        if user.confirmed:
            flash('Konta jau apstiprināts. Lūdzu, pieslēdzieties.', 'success')
        else:
            user.confirmed = True
            user.confirmed_on = datetime.utcnow()
            db.session.add(user)
            db.session.commit()
            flash('Jūs esat apstiprinājis savu kontu. Paldies!', 'success')
        return redirect(url_for('home'))

    @app.route('/thank_you')
    def thank_you():
        return render_template('thank_you.html', title='Paldies')

    @app.route('/create_idea', methods=['GET', 'POST'])
    @login_required
    def create_idea():
        if current_user.role != 'creator':
            flash('Idejas var izveidot tikai radītāji.', 'danger')
            return redirect(url_for('dashboard'))
            
        form = IdeaForm()
        if form.validate_on_submit():
            idea = Idea(
                title=form.title.data,
                description=form.description.data,
                category=form.category.data,
                user_id=current_user.id
            )
            db.session.add(idea)
            db.session.commit()

            for option_form in form.voting_options.entries:
                voting_option = VotingOption(option_text=option_form.form.option_text.data, idea_id=idea.id)
                db.session.add(voting_option)

            db.session.commit()
            flash('Jūsu ideja ir pievienota ar balsošanas iespējām!', 'success')
            return redirect(url_for('dashboard'))
        return render_template('create_idea.html', form=form)

    @app.route('/rang')
    def rang():
        all_ideas = Idea.query.all()
        like_form = LikeForm()  
        return render_template('rang.html', ideas=all_ideas, form=like_form)

    @app.route('/ideas')
    @login_required
    def ideas():
        all_ideas = Idea.query.all()
        return render_template('ideas.html', ideas=all_ideas)
    
    @app.route('/edit_idea/<int:idea_id>', methods=['GET', 'POST'])
    @login_required
    def edit_idea(idea_id):
        idea = Idea.query.get_or_404(idea_id)
        if idea.user_id != current_user.id:
            abort(403)
        form = IdeaForm(obj=idea)
        if form.validate_on_submit():
            idea.title = form.title.data
            idea.description = form.description.data
            idea.category = form.category.data

            existing_options = {option.id: option for option in idea.voting_options}

            # Update existing options or add new ones
            for option_form in form.voting_options:
                if option_form.option_text.data:
                    if option_form.id.data in existing_options:
                        existing_options[option_form.id.data].option_text = option_form.option_text.data
                    else:
                        new_option = VotingOption(option_text=option_form.option_text.data, idea_id=idea.id)
                        db.session.add(new_option)

            # Remove deleted options
            for option_id, option in existing_options.items():
                if option_id not in [opt.id.data for opt in form.voting_options]:
                    db.session.delete(option)

            db.session.commit()
            flash('Jūsu ideja ir atjaunināta!', 'success')
            return redirect(url_for('dashboard'))

        return render_template('edit_idea.html', form=form, idea=idea)




    @app.route('/delete_idea/<int:idea_id>', methods=['POST'])
    @login_required
    def delete_idea(idea_id):
        idea = Idea.query.get_or_404(idea_id)
        if idea.user_id != current_user.id:
            abort(403)
        try:
            db.session.delete(idea)
            db.session.commit()
            flash('Jūsu ideja ir dzēsta!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Kļūda, dzēšot ideju: {e}', 'danger')
        return redirect(url_for('ideas'))

    @app.route('/like_idea/<int:idea_id>', methods=['POST'])
    @login_required
    def like_idea(idea_id):
        if current_user.role != 'creator':
            flash('Patīk piešķiršana ir pieejama tikai radītājiem.', 'danger')
            return redirect(url_for('view_idea', idea_id=idea_id))

        idea = Idea.query.get_or_404(idea_id)
        like = Like.query.filter_by(user_id=current_user.id, idea_id=idea_id).first()
        if like:
            db.session.delete(like)
            db.session.commit()
            flash('Jūs esat noņēmuši patīk.', 'info')
        else:
            new_like = Like(user_id=current_user.id, idea_id=idea_id)
            db.session.add(new_like)
            db.session.commit()
            flash('Jūs esat piešķīruši patīk.', 'success')
        return redirect(url_for('rang'))

    @app.route('/comment_idea/<int:idea_id>', methods=['POST'])
    @login_required
    def comment_idea(idea_id):
        if current_user.role != 'creator':
            flash('Komentēšana ir pieejama tikai radītājiem.', 'danger')
            return redirect(url_for('view_idea', idea_id=idea_id))

        idea = Idea.query.get_or_404(idea_id)
        form = CommentForm()
        if form.validate_on_submit():
            comment = Comment(content=form.content.data, user_id=current_user.id, idea_id=idea_id)
            db.session.add(comment)
            db.session.commit()
            flash('Jūsu komentārs ir publicēts!', 'success')
        return redirect(url_for('view_idea', idea_id=idea_id))

    @app.route('/reply_comment/<int:comment_id>', methods=['POST'])
    @login_required
    def reply_comment(comment_id):
        if current_user.role != 'creator':
            flash('Atbildēšana ir pieejama tikai radītājiem.', 'danger')
            return redirect(url_for('view_idea', idea_id=parent_comment.idea_id))

        parent_comment = Comment.query.get_or_404(comment_id)
        idea_id = parent_comment.idea_id
        form = CommentForm()
        if form.validate_on_submit():
            reply = Comment(content=form.content.data, user_id=current_user.id, idea_id=idea_id, parent_id=comment_id)
            db.session.add(reply)
            db.session.commit()
            flash('Jūsu atbilde ir publicēta!', 'success')
        return redirect(url_for('view_idea', idea_id=idea_id))

    @app.route('/view_idea/<int:idea_id>', methods=['GET', 'POST'])
    @login_required
    def view_idea(idea_id):
        idea = Idea.query.get_or_404(idea_id)
        comments = Comment.query.filter_by(idea_id=idea_id).order_by(Comment.date_posted.desc()).all()
        voting_options = VotingOption.query.filter_by(idea_id=idea.id).all()
        comment_form = CommentForm()
        like_form = LikeForm()

        user_vote = Vote.query.filter_by(user_id=current_user.id, idea_id=idea_id).first()
        has_voted = user_vote is not None

        if request.method == 'POST' and 'voting_option' in request.form:
            if current_user.role != 'creator':
                flash('Balsošana ir pieejama tikai radītājiem.', 'danger')
            elif has_voted:
                flash('Jūs jau esat balsojis par šo ideju.', 'warning')
            else:
                selected_option_id = request.form.get('voting_option')
                selected_option = VotingOption.query.get(selected_option_id)
                if selected_option:
                    selected_option.votes += 1
                    db.session.commit()

                    vote = Vote(user_id=current_user.id, idea_id=idea_id, option_id=selected_option_id)
                    db.session.add(vote)
                    db.session.commit()

                    flash('Jūsu balsojums ir reģistrēts!', 'success')
                return redirect(url_for('view_idea', idea_id=idea_id))

        if current_user.role == 'creator' and comment_form.validate_on_submit() and 'content' in request.form:
            parent_id = comment_form.parent_id.data or None
            comment = Comment(content=comment_form.content.data, user_id=current_user.id, idea_id=idea_id, parent_id=parent_id)
            db.session.add(comment)
            db.session.commit()
            flash('Jūsu komentārs ir publicēts!', 'success')
            return redirect(url_for('view_idea', idea_id=idea_id))

        if current_user.role == 'creator' and like_form.validate_on_submit() and 'like_button' in request.form:
            existing_like = Like.query.filter_by(user_id=current_user.id, idea_id=idea_id).first()
            if (existing_like):
                flash('Jūs jau esat piešķīris patīk šai idejai.', 'warning')
            else:
                new_like = Like(user_id=current_user.id, idea_id=idea_id)
                db.session.add(new_like)
                db.session.commit()
                flash('Jūs esat piešķīruši patīk.', 'success')
            return redirect(url_for('view_idea', idea_id=idea_id))

        voting_labels = [option.option_text for option in voting_options]
        voting_votes = [option.votes for option in voting_options]

        return render_template('view_idea.html', 
                            idea=idea, 
                            comment_form=comment_form, 
                            like_form=like_form, 
                            comments=comments, 
                            voting_options=voting_options, 
                            voting_labels=voting_labels, 
                            voting_votes=voting_votes,
                            has_voted=has_voted)

    @app.route('/edit_profile', methods=['GET', 'POST'])
    @login_required
    def edit_profile():
        form = UpdateProfileForm()
        if form.validate_on_submit():
            current_user.username = form.username.data
            current_user.email = form.email.data
            db.session.commit()
            flash('Jūsu profils ir atjaunināts!', 'success')
            return redirect(url_for('dashboard'))
        elif request.method == 'GET':
            form.username.data = current_user.username
            form.email.data = current_user.email
        return render_template('edit_profile.html', form=form)

    @app.route('/change_password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        form = ChangePasswordForm()
        if form.validate_on_submit():
            if bcrypt.check_password_hash(current_user.password, form.current_password.data):
                current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                db.session.commit()
                flash('Jūsu parole ir atjaunināta!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Nepareiza pašreizējā parole.', 'danger')
        return render_template('change_password.html', form=form)

    @app.route('/contact', methods=['GET', 'POST'])
    def contact():
        form = ContactForm()
        if form.validate_on_submit():
            flash('Jūsu ziņojums ir nosūtīts!', 'success')
            return redirect(url_for('contact'))
        return render_template('contact.html', form=form)

    @app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
    @login_required
    def edit_comment(comment_id):
        comment = Comment.query.get_or_404(comment_id)
        if comment.user_id != current_user.id or (datetime.utcnow() - comment.date_posted).total_seconds() > 900:
            flash('Jūs vairs nevarat rediģēt šo komentāru.', 'danger')
            return redirect(url_for('some_view'))

        form = CommentForm(obj=comment)
        if form.validate_on_submit():
            comment.content = form.content.data
            db.session.commit()
            flash('Jūsu komentārs ir atjaunināts!', 'success')
            return redirect(url_for('some_view'))
        return render_template('edit_comment.html', form=form)

    @app.route('/delete_comment/<int:comment_id>', methods=['POST'])
    @login_required
    def delete_comment(comment_id):
        comment = Comment.query.get_or_404(comment_id)
        if comment.user_id != current_user.id or (datetime.utcnow() - comment.date_posted).total_seconds() > 900:
            flash('Jūs vairs nevarat dzēst šo komentāru.', 'danger')
            return redirect(url_for('view_idea', idea_id=comment.idea_id))

        try:
            db.session.delete(comment)
            db.session.commit()
            flash('Jūsu komentārs ir dzēsts!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Kļūda, dzēšot jūsu komentāru: {e}', 'danger')

        return redirect(url_for('view_idea', idea_id=comment.idea_id))

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)




























