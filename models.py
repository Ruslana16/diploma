from datetime import datetime
from extensions import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"

class Idea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('ideas', lazy=True))
    likes = db.relationship('Like', backref='idea', lazy=True)
    comments = db.relationship('Comment', backref='parent_idea', lazy=True)
    idea_votes = db.relationship('Vote', backref='parent_idea_votes', lazy=True)  # Renamed backref to 'parent_idea_votes'
    voting_options = db.relationship('VotingOption', backref='idea', lazy=True)

    def __repr__(self):
        return f"<Idea {self.title}>"

    @property
    def like_count(self):
        return Like.query.filter_by(idea_id=self.id).count()

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    idea_id = db.Column(db.Integer, db.ForeignKey('idea.id'), nullable=False)

    def __repr__(self):
        return f"<Like {self.user_id} - {self.idea_id}>"

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    idea_id = db.Column(db.Integer, db.ForeignKey('idea.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))

    def __repr__(self):
        return f"<Comment {self.content[:20]}>"
    
class VotingOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option_text = db.Column(db.String(100), nullable=False)
    votes = db.Column(db.Integer, default=0)
    idea_id = db.Column(db.Integer, db.ForeignKey('idea.id'), nullable=False)
    option_votes = db.relationship('Vote', backref='voting_option', lazy=True)  # Renamed backref to 'voting_option'

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    idea_id = db.Column(db.Integer, db.ForeignKey('idea.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('voting_option.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='user_votes')  # Renamed backref to 'user_votes'
    idea = db.relationship('Idea', backref='parent_idea_votes')  # Renamed backref to 'parent_idea_votes'
    option = db.relationship('VotingOption', backref='voting_option')  # Renamed backref to 'voting_option'











    






