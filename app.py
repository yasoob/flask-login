from flask import Flask,request,session,abort,redirect,render_template,make_response, url_for, flash
from flask.ext.sqlalchemy import SQLAlchemy
from werkzeug import generate_password_hash, check_password_hash
from forms import SignupForm, LoginForm
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///paste.db"
app.config['SECRET_KEY'] = os.urandom(24)

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    password = db.Column(db.String(120))
    email = db.Column(db.String(240))

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.set_password(password)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return '<User %r>' % self.name


@app.before_request
def check_user_status():
    if 'user_email' not in session:
        session['user_email'] = None
        session['user_name'] = None


@app.route('/', methods=('GET', 'POST'))
def home():
    if session['user_name']:
        users = User.query.all()
        return render_template('index.html', users=users)
    return redirect(url_for('login'),401)


@app.route('/login', methods=('GET', 'POST'))
def login():
    if session['user_email']:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            session['user_email'] = form.email.data
            session['user_name'] = user.name
            flash('Thanks for logging in')
            return redirect(url_for('home'))
        else:
            flash('Sorry! no user exists with this email and password')
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/signup', methods=('GET', 'POST'))
def signup():
    if session['user_email']:
        flash('you are already signed up')
        return redirect(url_for('home'))
    form = SignupForm()
    if form.validate_on_submit():
        user_email = User.query.filter_by(email=form.email.data).first()
        if user_email is None:
            user = User(form.name.data, form.email.data, form.password.data)
            db.session.add(user)
            db.session.commit()
            session['user_email'] = form.email.data
            session['user_name'] = form.name.data
            flash('Thanks for registering. You are now logged in!')
            return redirect(url_for('home'))
        else:
            flash("A User with that email already exists. Choose another one!", 'error')
            render_template('signup.html', form=form)
    return render_template('signup.html', form=form)


@app.route('/logout', methods=('GET', 'POST'))
def logout():
    session.pop('user_email', None)
    session.pop('user_name', None)
    flash("You were successfully logged out")
    return redirect(request.referrer or url_for('home'))

if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', port=8080, debug=True)
