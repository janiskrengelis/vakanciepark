from flask import Flask, render_template, request, redirect,url_for
#database
from flask_sqlalchemy import SQLAlchemy
#login and security & user
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_bcrypt import Bcrypt
#Forms
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, DateField
from wtforms.validators import InputRequired, Length, ValidationError
#datetime
import datetime

#App & database initialization
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config['SECRET_KEY'] = '2rmawkub@*vHLMgLr5pLuAnw'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
app.app_context().push()

#User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Create admin in terminal, in case there are none in database
def create_admin():
    email = input("Please enter an email: ")
    password = input("Please enter a password: ")
    name = input("Please enter a name: ")
    surname = input("Please enter a surname: ")
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, name=name, surname=surname, password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()
    return

#Database tables
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), nullable=False,unique=True)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(30), nullable=False)
    surname = db.Column(db.String(30), nullable=False)
    admin = db.Column(db.Boolean, nullable=False)
    def __repr__(self):
        return self.email

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start = db.Column(db.Date, nullable=False)
    end = db.Column(db.Date, nullable=False)
    place = db.Column(db.String(40), nullable=False)
    accommodation = db.Column(db.String(20), nullable=False)
    notes = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime,default=datetime.datetime.utcnow)
    user = db.Column(db.ForeignKey(User.id), nullable=False)
    users = db.relationship('User', backref=db.backref('reservations', lazy='dynamic'))

#Views for admin panel
class Userview(ModelView):
    column_display_pk = True 
    column_hide_backrefs = False
    column_list = ('id', 'email', 'name', 'surname', 'admin')
    def is_accessible(self):
        if current_user.is_authenticated:
            return current_user.admin
        else:
            return False

class Reservationview(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id','timestamp', 'start', 'end', 'place', 'accommodation', 'users')
    def is_accessible(self):
        if current_user.is_authenticated:
            return current_user.admin
        else:
            return False

#Admin screen config
admin = Admin(app)
admin.add_view(Userview(User, db.session))
admin.add_view(Reservationview(Reservation, db.session))


#Input forms
class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "E-mail"})
    name = StringField(validators=[InputRequired(), Length(min=1, max=30)], render_kw={"placeholder": "Name"})
    surname = StringField(validators=[InputRequired(), Length(min=1, max=30)], render_kw={"placeholder": "Surname"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "E-mail"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class ReservationForm(FlaskForm):
    start = DateField(validators=[InputRequired()], render_kw={"placeholder": "Start Date"})
    end = DateField(validators=[InputRequired()], render_kw={"placeholder": "End Date"})
    place = SelectField(validators=[InputRequired()],choices=["Eindhoven, NL","Zwolle NL","Hamburg, DE", "Antwerp BG"], render_kw={"placeholder": "Place"})
    accommodation = SelectField(validators=[InputRequired()],choices=["campsite","Caravan parking","Bungalo"], render_kw={"placeholder": "Accommodation type"})
    notes = StringField(validators=[Length(max=256)], render_kw={"placeholder": "Additional requests"})
    submit = SubmitField('submit')

#Routes
@app.route('/login', methods=["GET","POST"])
def login_page():
    if not current_user.is_authenticated:
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('main_page'))
        return render_template('login.html',form=form)
    else:
        return redirect(url_for('main_page'))

@app.route('/registration', methods=["GET","POST"])
def reg_page():
    if not current_user.is_authenticated:
        form = RegisterForm()

        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(email=form.email.data, name=form.name.data, surname=form.surname.data, password=hashed_password, admin=False)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login_page'))

        return render_template('registration.html',form=form)
    else:
        return redirect(url_for('main_page'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main_page'))

@app.route('/reservation', methods=['GET', 'POST'])
@login_required
def reservation():
    form = ReservationForm()
    if form.validate_on_submit():
        new_reservation = Reservation(start=form.start.data, end=form.end.data, place=form.place.data, accommodation=form.accommodation.data,notes=form.notes.data,user=current_user.get_id())
        db.session.add(new_reservation)
        db.session.commit()
        return redirect(url_for('main_page'))
    
    return render_template('reservation.html',form=form)

@app.route('/')
def main_page():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(threaded=True)