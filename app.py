from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask application
app = Flask(__name__)

# Application configuration
app.config['SECRET_KEY'] = b'G\x15\x9e\xe0\xec\xcf`<\xf3#\xb2\xf7xc\xc6)\xdc.\x86SX\xea\xa8\xcc'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Login successful!')
            return redirect(url_for('secret_page'))  # Redirect to secretPage after login
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        user = User.query.filter_by(email=email).first()
        error = None

        if user:
            error = 'Email address already in use.'
        
        if password != confirm_password:
            error = 'Passwords must match.'
        
        if error is not None:
            return render_template('signup.html', error=error, first_name=first_name, last_name=last_name, email=email)
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Thank you for registering!')
        return redirect(url_for('thank_you'))

    return render_template('signup.html')

@app.route('/secretPage')
def secret_page():
    return render_template('secretPage.html')

@app.route('/logout')
def logout():
    # Here you would handle logging out (e.g., clearing the session)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/thank_you')
def thank_you():
    return render_template('thankyou.html')

if __name__ == '__main__':
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
