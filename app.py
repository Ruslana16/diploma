from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from extensions import db, mail, login_manager, bcrypt, migrate
from forms import RegistrationForm, CommentForm, LikeForm, VotingOptionForm, LoginForm, ContactForm, IdeaForm, UpdateProfileForm, ChangePasswordForm
from models import User, Idea, Comment, Like, VotingOption, Vote
from utils import generate_confirmation_token, confirm_token
from emails import send_email
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from dotenv import load_dotenv
import os
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from wtforms.validators import DataRequired, Email, Optional

# Load environment variables
load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Ensure SECRET_KEY is set
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_hard_to_guess_string')

    # Initialize CSRF protection
    csrf = CSRFProtect(app)

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)  # Ensure CSRF protection is initialized

    # User Loader
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def inject_user():
        return dict(current_user=current_user)

    # Register blueprints or routes
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
                if user and bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    flash('Login successful.', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Login unsuccessful. Please check your username and password.', 'danger')
            except Exception as e:
                flash('An error occurred during login. Please try again.', 'danger')
                print(f'Error during login: {e}')
        return render_template('login.html', title='Login', form=form)

    @app.route('/logout')
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('home'))

    @app.route('/registration', methods=['GET', 'POST'])
    def registration():
        role = request.args.get('role')
        form = RegistrationForm()

        if role == 'creator':
                form.email.validators = [DataRequired(), Email()]
        else:
                form.email.validators = [Optional()]

        if form.validate_on_submit():
                email = form.email.data if role == 'creator' else None
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user = User(username=form.username.data, email=email, password=hashed_password, role=role, confirmed=False)
                db.session.add(user)
                db.session.commit()

                # Automatically log the user in after registration
                login_user(user)

                if user.email:
                    token = generate_confirmation_token(user.email)
                    confirm_url = url_for('confirm_email', token=token, _external=True)
                    html = render_template('activate.html', confirm_url=confirm_url)
                    send_email(user.email, 'Please confirm your email', html)

                flash('Thank you for registering! Please check your email for a confirmation link.', 'success')
                return redirect(url_for('dashboard'))

        return render_template('registration.html', title='Register', form=form, role=role)


    @app.route('/confirm/<token>')
    def confirm_email(token):
        try:
            email = confirm_token(token)
        except:
            flash('The confirmation link is invalid or has expired.', 'danger')
            return redirect(url_for('home'))

        user = User.query.filter_by(email=email).first_or_404()
        if user.confirmed:
            flash('Account already confirmed. Please login.', 'success')
        else:
            user.confirmed = True
            user.confirmed_on = datetime.utcnow()
            db.session.add(user)
            db.session.commit()
            flash('You have confirmed your account. Thanks!', 'success')
        return redirect(url_for('home'))

    @app.route('/thank_you')
    def thank_you():
        return render_template('thank_you.html', title='Thank You')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        user_ideas = Idea.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', ideas=user_ideas)

    @app.route('/create_idea', methods=['GET', 'POST'])
    @login_required
    def create_idea():
        if current_user.role != 'creator':
            flash('Only creators can create ideas.', 'danger')
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
            flash('Your idea has been added with voting options!', 'success')
            return redirect(url_for('dashboard'))
        return render_template('create_idea.html', form=form)

    @app.route('/rang')
    def rang():
        all_ideas = Idea.query.all()
        like_form = LikeForm()  # Create an instance of LikeForm
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
            abort(403)  # Forbidden if not the creator
        form = IdeaForm(obj=idea)
        if form.validate_on_submit():
            idea.title = form.title.data
            idea.description = form.description.data
            idea.category = form.category.data
            db.session.commit()
            flash('Your idea has been updated!', 'success')
            return redirect(url_for('dashboard'))
        return render_template('edit_idea.html', form=form, idea=idea)

    @app.route('/delete_idea/<int:idea_id>', methods=['POST'])
    @login_required
    def delete_idea(idea_id):
        idea = Idea.query.get_or_404(idea_id)
        if idea.user_id != current_user.id:
            abort(403)  # Forbidden if not the creator
        try:
            db.session.delete(idea)
            db.session.commit()
            flash('Your idea has been deleted!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting your idea: {e}', 'danger')
        return redirect(url_for('ideas'))

    @app.route('/like_idea/<int:idea_id>', methods=['POST'])
    @login_required
    def like_idea(idea_id):
        if current_user.role != 'creator':
            flash('Liking is only available for creators.', 'danger')
            return redirect(url_for('view_idea', idea_id=idea_id))

        idea = Idea.query.get_or_404(idea_id)
        like = Like.query.filter_by(user_id=current_user.id, idea_id=idea_id).first()
        if like:
            db.session.delete(like)
            db.session.commit()
            flash('You have unliked the idea.', 'info')
        else:
            new_like = Like(user_id=current_user.id, idea_id=idea_id)
            db.session.add(new_like)
            db.session.commit()
            flash('You have liked the idea.', 'success')
        return redirect(url_for('rang'))

    @app.route('/comment_idea/<int:idea_id>', methods=['POST'])
    @login_required
    def comment_idea(idea_id):
        if current_user.role != 'creator':
            flash('Commenting is only available for creators.', 'danger')
            return redirect(url_for('view_idea', idea_id=idea_id))

        idea = Idea.query.get_or_404(idea_id)
        form = CommentForm()
        if form.validate_on_submit():
            comment = Comment(content=form.content.data, user_id=current_user.id, idea_id=idea_id)
            db.session.add(comment)
            db.session.commit()
            flash('Your comment has been posted!', 'success')
        return redirect(url_for('view_idea', idea_id=idea_id))

    @app.route('/reply_comment/<int:comment_id>', methods=['POST'])
    @login_required
    def reply_comment(comment_id):
        if current_user.role != 'creator':
            flash('Replying is only available for creators.', 'danger')
            return redirect(url_for('view_idea', idea_id=parent_comment.idea_id))

        parent_comment = Comment.query.get_or_404(comment_id)
        idea_id = parent_comment.idea_id
        form = CommentForm()
        if form.validate_on_submit():
            reply = Comment(content=form.content.data, user_id=current_user.id, idea_id=idea_id, parent_id=comment_id)
            db.session.add(reply)
            db.session.commit()
            flash('Your reply has been posted!', 'success')
        return redirect(url_for('view_idea', idea_id=idea_id))

    @app.route('/view_idea/<int:idea_id>', methods=['GET', 'POST'])
    @login_required
    def view_idea(idea_id):
        idea = Idea.query.get_or_404(idea_id)
        comments = Comment.query.filter_by(idea_id=idea_id).order_by(Comment.date_posted.desc()).all()
        voting_options = VotingOption.query.filter_by(idea_id=idea.id).all()
        comment_form = CommentForm()
        like_form = LikeForm()

        # Check if the user has already voted
        user_vote = Vote.query.filter_by(user_id=current_user.id, idea_id=idea_id).first()
        has_voted = user_vote is not None

        # Handling vote form submission
        if request.method == 'POST' and 'voting_option' in request.form:
            if current_user.role != 'creator':
                flash('Voting is only available for creators.', 'danger')
            elif has_voted:
                flash('You have already voted on this idea.', 'warning')
            else:
                selected_option_id = request.form.get('voting_option')
                selected_option = VotingOption.query.get(selected_option_id)
                if selected_option:
                    selected_option.votes += 1
                    db.session.commit()

                    # Record the vote
                    vote = Vote(user_id=current_user.id, idea_id=idea_id, option_id=selected_option_id)
                    db.session.add(vote)
                    db.session.commit()

                    flash('Your vote has been recorded!', 'success')
                return redirect(url_for('view_idea', idea_id=idea_id))

        # Handling comment form submission
        if current_user.role == 'creator' and comment_form.validate_on_submit() and 'content' in request.form:
            parent_id = comment_form.parent_id.data or None
            comment = Comment(content=comment_form.content.data, user_id=current_user.id, idea_id=idea_id, parent_id=parent_id)
            db.session.add(comment)
            db.session.commit()
            flash('Your comment has been posted!', 'success')
            return redirect(url_for('view_idea', idea_id=idea_id))

        # Handling like form submission
        if current_user.role == 'creator' and like_form.validate_on_submit() and 'like_button' in request.form:
            existing_like = Like.query.filter_by(user_id=current_user.id, idea_id=idea_id).first()
            if existing_like:
                flash('You have already liked this idea.', 'warning')
            else:
                new_like = Like(user_id=current_user.id, idea_id=idea_id)
                db.session.add(new_like)
                db.session.commit()
                flash('You have liked the idea.', 'success')
            return redirect(url_for('view_idea', idea_id=idea_id))

        # Prepare data for Chart.js
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
            flash('Your profile has been updated!', 'success')
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
                flash('Your password has been updated!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect current password.', 'danger')
        return render_template('change_password.html', form=form)

    @app.route('/contact', methods=['GET', 'POST'])
    def contact():
        form = ContactForm()
        if form.validate_on_submit():
            flash('Your message has been sent!', 'success')
            return redirect(url_for('contact'))
        return render_template('contact.html', form=form)

    @app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
    @login_required
    def edit_comment(comment_id):
        comment = Comment.query.get_or_404(comment_id)
        if comment.user_id != current_user.id or (datetime.utcnow() - comment.date_posted).total_seconds() > 900:
            flash('You cannot edit this comment anymore.', 'danger')
            return redirect(url_for('some_view'))

        form = CommentForm(obj=comment)
        if form.validate_on_submit():
            comment.content = form.content.data
            db.session.commit()
            flash('Your comment has been updated!', 'success')
            return redirect(url_for('some_view'))
        return render_template('edit_comment.html', form=form)

    @app.route('/delete_comment/<int:comment_id>', methods=['POST'])
    @login_required
    def delete_comment(comment_id):
        comment = Comment.query.get_or_404(comment_id)
        if comment.user_id != current_user.id or (datetime.utcnow() - comment.date_posted).total_seconds() > 900:
            flash('You cannot delete this comment anymore.', 'danger')
            return redirect(url_for('view_idea', idea_id=comment.idea_id))

        try:
            db.session.delete(comment)
            db.session.commit()
            flash('Your comment has been deleted!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting your comment: {e}', 'danger')

        return redirect(url_for('view_idea', idea_id=comment.idea_id))

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)


















