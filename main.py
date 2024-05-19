from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///temp.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =========================================================== #
# -=-=-=-=-=-=-=-=-=-=-=- M O D E L S -=-=-=-=-=-=-=-=-=-=-=- #
# =========================================================== #

class Rank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)

    def __repr__(self):
        return '<Rank %r>' % self.name

user_rank_association = db.Table('user_rank',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('rank_id', db.Integer, db.ForeignKey('rank.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    ranks = db.relationship('Rank', secondary=user_rank_association, backref=db.backref('users', lazy='dynamic'))
    confirmed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %r>' % self.username
    
class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Page %r>' % self.title

# ========================================================= #
# -=-=-=-=-=-=-=-=-=-=-=- F O R M S -=-=-=-=-=-=-=-=-=-=-=- #
# ========================================================= #

# Account signup
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

# =========================================================== #
# -=-=-=-=-=-=-=-=-=-=-=- R O U T E S -=-=-=-=-=-=-=-=-=-=-=- #
# =========================================================== #

# Index
@app.route('/')
def index():
    pages = Page.query.all()
    return render_template('index.html', pages=pages)

# Create page
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        page = Page(title=title, content=content)
        db.session.add(page)
        db.session.commit()
        return redirect(url_for('page', page_id=page.id))
    return render_template('create.html')

# Page
@app.route('/<int:page_id>')
def page(page_id):
    page = Page.query.get_or_404(page_id)
    return render_template('page.html', page=page)

# Edit
@app.route('/edit/<int:page_id>', methods=['GET', 'POST'])
@login_required
def edit(page_id):
    page = Page.query.get_or_404(page_id)
    if request.method == 'POST':
        page.title = request.form['title']
        page.content = request.form['content']
        db.session.commit()
        return redirect(url_for('page', page_id=page.id))
    return render_template('edit.html', page=page)

# Delete
@app.route('/delete/<int:page_id>', methods=['POST'])
@login_required
def delete(page_id):
    page = Page.query.get_or_404(page_id)
    db.session.delete(page)
    db.session.commit()
    return redirect(url_for('index')) # Redirect to the index page after deletion

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('You have been logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

# Main
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
