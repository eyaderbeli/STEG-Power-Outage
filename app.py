from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, DateTimeField, SubmitField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.secret_key = os.getenv('SECRET_KEY') or 'default_secret_key'
ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY')


db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    location = db.Column(db.String(255), nullable=True)  
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=True)
    area_id = db.Column(db.Integer, db.ForeignKey('area.id'), nullable=True)
    city = db.relationship('City', backref='users', lazy=True)
    area = db.relationship('Area', backref='users', lazy=True)
   

    def get_reset_token(self, expires_sec=1800):
       
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id, 'exp': expires_sec})

    @staticmethod
    def verify_reset_token(token):
      
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            
            payload = s.loads(token)
            user_id = payload['user_id']
            expiration_time = payload['exp']
           
            if expiration_time < datetime.utcnow().timestamp():
                return None 
        except:
            return None  
        return User.query.get(user_id)
   
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    category = db.Column(db.String(50), nullable=False)
    report = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(120), nullable=False)  
    location = db.Column(db.String(255), nullable=True)
    full_address = db.Column(db.String(255), nullable=True)
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=True)
    area_id = db.Column(db.Integer, db.ForeignKey('area.id'), nullable=True)


class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    areas = db.relationship('Area', backref='city', lazy=True)

class Area(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    power_line = db.Column(db.String(100), nullable=False)
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=False)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=150)])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[InputRequired()])
    admin_secret_key = PasswordField('Admin Secret Key')  # Field for secret key (only shown if admin is selected)
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=150)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[InputRequired()])
    admin_secret_key = PasswordField('Admin Secret Key')  # Add this line for admin key input
    submit = SubmitField('Register')

class ReportForm(FlaskForm):
    category = SelectField('Category', choices=[
        ("Power Outage", "Power Outage"),
        ("Power Fluctuation", "Power Fluctuation"),
        ("Circuit Breaker Issue", "Circuit Breaker Issue"),
        ("Voltage Drop", "Voltage Drop"),
        ("General Maintenance", "General Maintenance"),
        ("Other", "Other")
    ], validators=[InputRequired()])

    date = DateTimeField('Date', format='%Y-%m-%d', validators=[InputRequired()])
    report = TextAreaField('Report', validators=[InputRequired()])
    username = StringField('Username', validators=[InputRequired()], render_kw={"readonly": True})
    location = StringField('Location', validators=[InputRequired()], render_kw={"readonly": True})
    full_address = StringField('Full Address', validators=[InputRequired()])
    city = SelectField('City', coerce=int, validators=[InputRequired()])
    area = SelectField('Area', coerce=int, validators=[InputRequired()])
    submit = SubmitField('Submit Report')

class LocationForm(FlaskForm):
    city = SelectField('City', coerce=int, validators=[InputRequired()])
    area = SelectField('Area', coerce=int, validators=[InputRequired()])
    location = StringField('Location', validators=[InputRequired()], render_kw={"readonly": True})
    submit = SubmitField('Update Location')

class AdminNotifyForm(FlaskForm):
    city = SelectField('City', coerce=int, validators=[InputRequired()])
    area = SelectField('Area', coerce=int, validators=[InputRequired()])
    message = TextAreaField('Message', validators=[InputRequired()], render_kw={"rows": 5, "placeholder": "Enter your message"})
    submit = SubmitField('Send Notification')


# Routes
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data
        admin_secret_key = form.admin_secret_key.data

        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            
            if role == 'admin':
                if admin_secret_key == ADMIN_SECRET_KEY:
                    
                    session["user_id"] = user.id
                    session["username"] = user.username
                    session["role"] = user.role
                    flash(f"Welcome back, {user.username}!", "success")
                    return redirect(url_for("admin_dashboard"))
                else:
                    flash("Incorrect admin secret key.", "danger")
                    return redirect(url_for("login"))
            elif role == 'user':
                
                session["user_id"] = user.id
                session["username"] = user.username
                session["role"] = user.role
                flash(f"Welcome back, {user.username}!", "success")
                return redirect(url_for("user_dashboard"))
            else:
                flash("Invalid role selected.", "danger")
                return redirect(url_for("login"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html", form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        role = form.role.data
        admin_secret_key = form.admin_secret_key.data

        
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        
        if role == "admin" and admin_secret_key != ADMIN_SECRET_KEY:
            flash("Incorrect admin secret key.", "danger")
            return redirect(url_for("register"))

        
        assigned_role = 'admin' if role == 'admin' else 'user'

    
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)

      
        new_user = User(username=username, password=hashed_password, role=assigned_role)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful!", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email Address', validators=[InputRequired()])


@app.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(username=email).first()

        if user:
           
            reset_token = user.get_reset_token()  

            
            msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'To reset your password, visit the following link: {url_for("reset_password", token=reset_token, _external=True)}'
            try:
                mail.send(msg)
                flash("Password reset instructions have been sent to your email.", "info")
            except Exception as e:
                flash("There was an issue sending the reset email. Please try again.", "danger")

        else:
            flash("No account found with that email.", "danger")
        return redirect(url_for('forgot_password'))

    return render_template("forgot_password.html", form=form)

@app.route('/reset-password/<token>', methods=["GET", "POST"])
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash("That is an invalid or expired token.", "danger")
        return redirect(url_for('forgot_password'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been updated!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)
    
@app.route("/update-location", methods=["GET", "POST"])
def update_location():
   
    if "user_id" not in session:
        flash("Please log in to access this page.", "danger")
        return redirect(url_for("login"))

    
    user = db.session.get(User, session["user_id"])
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("login"))

   
    form = LocationForm()

    
    cities = City.query.all()
    form.city.choices = [(city.id, city.name) for city in cities]
    print("Cities fetched from database:", cities)  # Debugging

    
    if request.method == "GET":
        form.city.data = user.city_id
        form.area.data = user.area_id
        if user.city_id and user.area_id:
            city = City.query.get(user.city_id)
            area = Area.query.get(user.area_id)
            form.location.data = f"{area.name}, {city.name}" if city and area else ""

    
    selected_city_id = form.city.data or user.city_id
    areas = Area.query.filter_by(city_id=selected_city_id).all()
    form.area.choices = [(area.id, area.name) for area in areas]
    print(f"Areas fetched for selected city ({selected_city_id}):", areas)  # Debugging

    
    if form.validate_on_submit():
        try:
            
            city = City.query.get(form.city.data)
            area = Area.query.get(form.area.data)

            
            user.city_id = form.city.data
            user.area_id = form.area.data
            user.location = f"{area.name}, {city.name}" if city and area else "N/A"

            
            db.session.commit()
            print(f"Updated user location: {user.location}")  # Debugging
            flash("Location updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            print(f"Error updating location: {e}")  
            flash("Failed to update location. Please try again.", "danger")
        return redirect(url_for("user_dashboard"))

    return render_template("update_location_form.html", form=form, cities=cities)


@app.route("/report", methods=["GET", "POST"])
def report():
    if "user_id" not in session:
        flash("Please log in to submit a report.", "danger")
        return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])
    form = ReportForm()

    
    cities = City.query.all()
    form.city.choices = [(city.id, city.name) for city in cities]

    
    form.username.data = user.username
    if user.city_id and user.area_id:
        city = City.query.get(user.city_id)
        area = Area.query.get(user.area_id)
        form.location.data = f"{area.name}, {city.name}"

   
    selected_city_id = form.city.data or user.city_id
    areas = Area.query.filter_by(city_id=selected_city_id).all()
    form.area.choices = [(area.id, area.name) for area in areas]

    if form.validate_on_submit():
        try:
            city = City.query.get(form.city.data)
            area = Area.query.get(form.area.data)
            form.location.data = f"{area.name}, {city.name}"

           
            new_report = Report(
                date=form.date.data,
                category=form.category.data,
                report=form.report.data,
                username=form.username.data,  # Use username from the form
                location=form.location.data,
                full_address=form.full_address.data,
                city_id=form.city.data,
                area_id=form.area.data
            )
            db.session.add(new_report)
            db.session.commit()

            flash("Your issue has been reported!", "success")
            return redirect(url_for("user_dashboard"))

        except Exception as e:
            db.session.rollback()
            print(f"Error submitting report: {e}")
            flash("An error occurred while submitting the report. Please try again.", "danger")

    return render_template("report_form.html", form=form)

@app.route("/dashboard")
def user_dashboard():
    if "user_id" not in session:
        flash("Please log in to access the dashboard.", "danger")
        return redirect(url_for("login"))

   
    user = db.session.get(User, session["user_id"])
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    
    reports = Report.query.filter_by(username=user.username).all()
    # Debugging logs to ensure correct data is being fetched
    print(f"User Data: ID={user.id}, Username={user.username}, Location={user.location}")
    print(f"Reports Found: {len(reports)}")

    return render_template("dashboard.html", user=user, reports=reports)


@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("login"))

    
    users = User.query.all()
    reports = Report.query.all()

    
    reports_by_category = {}
    for report in reports:
        category = report.category
        if category not in reports_by_category:
            reports_by_category[category] = []
        reports_by_category[category].append(report)

    
    cities = {city.id: city.name for city in City.query.all()}
    areas = {area.id: area.name for area in Area.query.all()}

   
    for user in users:
        if user.city_id and user.area_id:
            city_name = cities.get(user.city_id, "Unknown City")
            area_name = areas.get(user.area_id, "Unknown Area")
            user.location = f"{area_name}, {city_name}"
        else:
            user.location = "N/A"

    return render_template(
        "admin_dashboard.html",
        users=users,
        reports=reports,
        reports_by_category=reports_by_category,
        notifications=None  
    )


@app.route("/admin/notify", methods=["GET", "POST"])
def admin_notify():
    if "user_id" not in session or session.get("role") != "admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("login"))

    cities = City.query.all()  
    areas = Area.query.all()  

    form = AdminNotifyForm()

    
    form.city.choices = [(city.id, city.name) for city in cities]
    form.area.choices = [(area.id, area.name) for area in areas]

    if form.validate_on_submit():
        city_id = form.city.data
        area_id = form.area.data
        message = form.message.data

        if not city_id or not area_id or not message:
            flash("All fields are required.", "danger")
            return redirect(url_for("admin_notify"))

        
        users_in_area = User.query.filter_by(city_id=city_id, area_id=area_id).all()

        
        for user in users_in_area:
            try:
                msg = Message(
                    "Outage Notification",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[user.username] 
                )
                msg.body = f"Dear {user.username},\n\n{message}\n\nThank you."
                mail.send(msg)
            except Exception as e:
                print(f"Failed to send email to {user.username}: {e}")

        flash("Notification sent successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_notify_form.html", form=form, cities=cities, areas=areas)

@app.route('/get-area-details/<int:area_id>', methods=["GET"])
def get_area_details(area_id):
    try:
        area = Area.query.get(area_id)
        if area:
            return jsonify({
                "id": area.id,
                "name": area.name,
                "city_name": area.city.name
            })
        else:
            return jsonify({"error": "Area not found"}), 404
    except Exception as e:
        print(f"Error fetching area details: {e}")
        return jsonify({"error": "Server error"}), 500

@app.route('/get-areas/<int:city_id>', methods=["GET"])
def get_areas(city_id):
    try:
        
        areas = Area.query.filter_by(city_id=city_id).all()
        
        return jsonify({
            "areas": [{"id": area.id, "name": area.name} for area in areas]
        })
    except Exception as e:
        print(f"Error fetching areas for city {city_id}: {e}")
        return jsonify({"error": "Failed to fetch areas"}), 500


@app.route("/confirm_restoration/<int:report_id>", methods=["POST"])
def confirm_restoration(report_id):
    if "user_id" not in session:
        flash("Please log in to confirm restoration.", "danger")
        return redirect(url_for("login"))

    report = Report.query.get(report_id)
    if report:
        report.restoration_confirmed = True
        db.session.commit()
        flash("Thank you for confirming power restoration.", "success")
    else:
        flash("Report not found.", "danger")

    return redirect(url_for("user_dashboard"))

@app.route("/historical-outages")
def historical_outages():
    if "user_id" not in session:
        flash("Please log in to view historical outages.", "danger")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    reports = Report.query.filter_by(user_email=user.username, category="Outage").all()
    return render_template("historical_outages.html", reports=reports)



@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
