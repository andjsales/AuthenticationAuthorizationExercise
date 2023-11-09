from flask import Flask, render_template, redirect, request, session, flash, url_for, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from models import User, db, connect_db, Feedback
from forms import RegistrationForm, LoginForm, FeedbackForm
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///authentication'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecret'
migrate = Migrate(app, db)
connect_db(app)


@app.context_processor
def inject_user():
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])
    else:
        g.user = None
    return dict(user=g.user)


@app.route('/')
def homepage():
    """
    redirects to register page 
    """
    return redirect('/register')


@app.route('/register')
def show_register_form():
    """
    generates registration form 
    """
    form = RegistrationForm()
    return render_template('register.html', form=form)


@app.route('/register', methods=["POST"])
def process_register_form():
    """
    Shows a form that when submitted will register/create a user
    """
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
            return redirect(url_for('show_user', username=username))
        else:
            form.username.errors = ['Invalid username/password']
    return render_template('login.html', form=form)


@app.route('/users/<string:username>')
def show_user(username):
    """
    Shows information about given user
    Shows all feedback from user
    """
    if 'user_id' not in session:
        flash('You must be logged in to view this page.', 'danger')
        return redirect('/login')

    logged_in_user = User.query.get(session['user_id'])
    user = User.query.filter_by(username=username).first_or_404()

    if logged_in_user.username != username:
        flash('You are not authorized to view this page.', 'danger')
        return redirect('/login')

    feedback = Feedback.query.filter_by(user_id=logged_in_user.id).all()
    return render_template('secret.html', user=user, feedback=feedback)


@app.route('/users/<string:username>/delete', methods=['POST'])
def delete_user(username):
    """
    Remove the user from the database 
    Deletes all of their feedback
    """
    if 'username' not in session or username != session['username']:
        flash('You are not authorized to perform this action.', 'danger')
        return redirect('/login')
    user = User.query.filter_by(username=username).first_or_404()
    Feedback.query.filter_by(username=username).delete()
    db.session.delete(user)
    db.session.commit()

    session.pop('username', None)
    flash('Your account and all associated feedback have been deleted.', 'success')
    return redirect(url_for('homepage'))


@app.route('/users/<string:username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """
    Display a form to add feedback
    Add a new piece of feedback
    """
    if 'user_id' not in session:
        flash('You must be logged in to add feedback.', 'danger')
        return redirect(url_for('show_login_form'))

    logged_in_user = User.query.get(session['user_id'])
    if logged_in_user.username != username:
        flash('You are not authorized to add feedback for this user.', 'danger')
        return redirect(url_for('show_login_form'))

    form = FeedbackForm()
    if form.validate_on_submit():
        new_feedback = Feedback(
            title=form.title.data,
            content=form.content.data,
            user_id=logged_in_user.id
        )
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback added!', 'success')
        return redirect(url_for('show_user', username=logged_in_user.username))
    return render_template('add_feedback.html', form=form, username=username)


@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    """
    Display a form to edit feedback
    Update a specific piece of feedback
    """
    feedback = Feedback.query.get_or_404(feedback_id)
    logged_in_user = User.query.get(session['user_id'])

    if feedback.user_id != logged_in_user.id:
        flash('You do not have permission to edit this feedback.', 'danger')
        return redirect(url_for('show_user', username=logged_in_user.username))

    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash('Feedback updated!', 'success')
        return redirect(url_for('show_user', username=logged_in_user.username))

    return render_template('update_feedback.html', form=form, feedback_id=feedback_id)


@app.route('/feedback/<int:feedback_id>/delete', methods=['GET', 'POST'])
def delete_feedback(feedback_id):
    """
    Delete a specific piece of feedback
    """
    feedback = Feedback.query.get_or_404(feedback_id)
    logged_in_user = User.query.get(session['user_id'])

    if feedback.user_id != logged_in_user.id:
        flash('You do not have permission to delete this feedback.', 'danger')
        return redirect(url_for('show_user', username=logged_in_user.username))

    db.session.delete(feedback)
    db.session.commit()
    flash('Feedback deleted!', 'success')
    return redirect(url_for('show_user', username=logged_in_user.username))


@app.route('/logout')
def logout_user():
    """
    Logout the current user
    """
    session.pop('user_id')
    flash("Goodbye!", "info")
    return redirect('/login')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
