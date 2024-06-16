from app import app, db
from models import User
from extensions import bcrypt

def create_admin_user():
    with app.app_context():
        username = "admin"
        email = "ruslanaankovska@gmail.com"
        password = "adminpassword"
        
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print("Admin user already exists.")
        else:
            # Create new admin user
            admin_user = User(username=username, email=email, password=hashed_password, role='admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully.")

if __name__ == '__main__':
    create_admin_user()
