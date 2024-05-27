
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate


db = SQLAlchemy()
mail = Mail()
login_manager = LoginManager()
bcrypt = Bcrypt()
migrate = Migrate()









