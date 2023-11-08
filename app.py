from flask import Flask, render_template, redirect, request, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from models import User, db, connect_db
from forms import RegistrationForm, LoginForm
from flask_bcrypt import Bcrypt


app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///authentication'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecret'

connect_db(app)


@app.route('/')
def homepage():
    return redirect('/register')


@app.route('/register')
def show_register_form():
    """
    - show registration form 
    """
    form = RegistrationForm()  # Instantiate your registration form
    return render_template('register.html', form=form)


@app.route('/register', methods=["POST"])
def process_register_form():
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            password=hashed_password,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data
        )
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html', form=form)


@app.route('/login')
def show_login_form():
    """
    - showing the login form  
    - when submitted will login a user
    """
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/login', methods=["POST"])
def process_login_form():
    """
    - process login form
    - go to /secret if user is authenticated
    """
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.authenticate(username, password)
        if user:
            session['user_id'] = user.id
            return redirect(url_for('logged_in_page', username=username))
        else:
            form.username.errors = ['Invalid username/password']
    return render_template('login.html', form=form)


@app.route('/users/<string:username>')
def logged_in_page(username):
    user = None
    username = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        username = user.username
    return render_template('secret.html', user=user, username=username)


@app.route('/logout')
def logout_user():
    session.pop('user_id')
    flash("Goodbye!", "info")
    return redirect('/login')


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(debug=True)
