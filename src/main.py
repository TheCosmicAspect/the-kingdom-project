from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from dotenv import load_dotenv
from utils.decorators import logout_required
from flask_mail import Mail

load_dotenv()

app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =========================================================== #
# -=-=-=-=-=-=-=-=-=-=-=- M O D E L S -=-=-=-=-=-=-=-=-=-=-=- #
# =========================================================== #

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    display_name = db.Column(db.String(100))
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    is_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_theologian = db.Column(db.Boolean, nullable=False, default=False)
    is_writer = db.Column(db.Boolean, nullable=False, default=False)
    is_historian = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(
        self, username, email, password, is_confirmed=False, is_admin=False, is_theologian=False, is_writer=False, is_historian=False 
    ):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password, method='pbkdf2:sha256')
        self.created_on = datetime.now()
        self.is_confirmed = is_confirmed
        self.is_admin = is_admin
        self.is_theologian = is_theologian
        self.is_writer = is_writer
        self.is_historian = is_historian

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
    return render_template('core/index.html', pages=pages)

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
    return render_template('pages/create.html')

# Page
@app.route('/<int:page_id>')
def page(page_id):
    page = Page.query.get_or_404(page_id)
    return render_template('pages/page.html', page=page)

# Edit
@app.route('/edit/<int:page_id>', methods=['GET', 'POST'])
@login_required
def edit(page_id):
    page = Page.query.get_or_404(page_id)
    if request.method == 'POST':
        page.title = request.form['title']
        page.content = request.form['content']
        db.session.commit()
        return redirect(url_for('pages/page', page_id=page.id))
    return render_template('core/edit.html', page=page)

# Delete
@app.route('/delete/<int:page_id>', methods=['POST'])
@login_required
def delete(page_id):
    page = Page.query.get_or_404(page_id)
    db.session.delete(page)
    db.session.commit()
    return redirect(url_for('core/index')) # Redirect to the index page after deletion

# Login
@app.route('/login', methods=['GET', 'POST'])
@logout_required
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('You have been logged in!', 'success')
            return redirect(url_for('core/index'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('accounts/login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('core/index'))

# Signup
@app.route('/signup', methods=['GET', 'POST'])
@logout_required
def signup():
    from utils.email import send_email
    from accounts.token import confirm_token, generate_token
    form = SignupForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()

        token = generate_token(new_user.email)
        confirm_url = url_for("confirm_email", token=token, _external=True)
        html = render_template("accounts/confirm_email.html", confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(new_user.email, subject, html)

        login_user(new_user)

        flash("A confirmation email has been sent via email.", "success")
        return redirect(url_for('login'))
    return render_template('accounts/signup.html', form=form)

# Confirm email
@app.route("/confirm/<token>")
@login_required
def confirm_email(token):
    from accounts.token import confirm_token, generate_token
    if current_user.is_confirmed:
        flash("Account already confirmed.", "success")
        return redirect(url_for("core.home"))
    email = confirm_token(token)
    user = User.query.filter_by(email=current_user.email).first_or_404()
    if user.email == email:
        user.is_confirmed = True
        db.session.add(user)
        db.session.commit()
        flash("You have confirmed your account. Thanks!", "success")
    else:
        flash("The confirmation link is invalid or has expired.", "danger")
    return redirect(url_for("core.home"))

# Main
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
