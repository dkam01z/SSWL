from functools import wraps
from flask.sessions import NullSession
from wtforms.fields.core import BooleanField, DateField, DecimalField, FloatField, IntegerField, SelectField, SelectMultipleField, TimeField

from flask import Flask , render_template, flash, redirect, url_for , session , logging, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField,PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps
import socket
from flask_admin import Admin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_admin.contrib.sqla import ModelView
from wtforms import validators
from wtforms.fields.html5 import EmailField
from flask import blueprints

import email_validator
from datetime import datetime
import stripe
import json
import os
from flask import jsonify

app = Flask(__name__, static_folder='templates',
            static_url_path='', template_folder='templates')
app.config.from_pyfile('config.cfg')

app.secret_key = 'SECRET123'

socket.getaddrinfo('127.0.0.1', 5000)

# Adjust MySQL
app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_51JwcNHGRdaLZqAsn471bhT6wudwnnIgd5Qw60rPdBHe0zTE3dNdy75m48hFtqkbGffDfT9UyoAvOoqPGOJj6R9k8008yG075hU'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_51JwcNHGRdaLZqAsnPHbMePhcH4YliIzsU0SoUXJJZGmpTUIztj8bO6YGyzVmEzn5QwQcUN7Y22DyVyyJVxopMP7600hu1tZfrB'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'SECRET123'
app.config['MYSQL_DB'] = 'sswl'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

stripe.api_key = app.config['STRIPE_SECRET_KEY']
#INITIALIZE MYSQL
mysql = MySQL(app)


@app.route("/")
def index():
    return render_template('home.html')

def calculate_order_amount(items):
    # Replace this constant with a calculation of the order's amount
    # Calculate the order total on the server to prevent
    # people from directly manipulating the amount on the client
    return 1400


@app.route('/create-payment-intent', methods=['POST'])
def create_payment():
    try:
        data = json.loads(request.data)
        # Create a PaymentIntent with the order amount and currency
        intent = stripe.PaymentIntent.create(
            amount=calculate_order_amount(data['items']),
            currency='eur',
            automatic_payment_methods={
                'enabled': True,
            },
        )
        return jsonify({
            'clientSecret': intent['client_secret']
        })
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/events')
def events():
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM events")
    events = cur.fetchall()

    if result > 0:
        return render_template('events.html', events=events)
    else:
        msg = 'No events found'
        return render_template('events.html', msg=msg)
    cur.close()




class RegisterForm(Form):
    firstname = StringField('First Name', [validators.Length(min=1 , max=50)])
    surname = StringField('Surname', [validators.Length(min=1,max=25)])
    number = StringField('Number', [validators.Length(min=7, max=14)])
    email = EmailField('Email address', [validators.DataRequired(), validators.Email()])
    sfirstname = StringField('Student firstname', [validators.Length(min=1,max=50)])
    ssurname = StringField('Student Surname', [validators.Length(min=1,max=50)])
    password = PasswordField('password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Password does not match!')
    ])
    confirm = PasswordField('Confirm Password')
    fgroup = SelectField('Select form group', choices=['Mr BotMan' , 'Mr Embassador', 'Mr Mike', 'Miss Puff', 'Miss many'])
    ygroup = SelectField('Select year group' , choices=['Year 10', 'Year 11', 'Year 12', 'Year 13'])



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        firstname = form.firstname.data
        surname = form.surname.data
        email = form.email.data
        number = form.number.data
        sfirstname = form.sfirstname.data
        ssurname = form.ssurname.data
        password = sha256_crypt.encrypt(str(form.password.data))
        fgroup = form.fgroup.data
        ygroup = form.ygroup.data
        
        cur = mysql.connection.cursor()
        x = cur.execute("SELECT * FROM PARENTS WHERE email=(%s)", (email,))
        if int(x) == 0:
            cur.execute("INSERT INTO parents(firstname, surname, email, number, password) VALUES(%s,%s,%s,%s,%s)", (firstname,surname,email, number,password))
            cur.execute("INSERT INTO student(PARENT_ID, sfirstname, ssurname, fgroup, ygroup)  VALUES(LAST_INSERT_ID(),%s,%s,%s,%s)", (sfirstname,ssurname,fgroup,ygroup))
        else:
            flash("Email already exists, try another email", "danger")
            return redirect(url_for('register'))

        #commit
        mysql.connection.commit()
        #close connection
        cur.close()
        #flash
        flash('You have successfully registered! You can login.', 'success')
        
        return redirect(url_for('index'))
    return render_template('register.html', form=form)



def is_logged_in(f):
    @wraps(f)
    def wrap(*args , **kwargs):
        if 'logged_in' in session:
            return f(*args , **kwargs)
        else:
            flash('Unauthorized, please attempt to login', 'danger')
            return redirect(url_for('login'))
    return wrap

def Alreadyloggedin(f):
    @wraps(f)
    def wrap(*args , **kwargs):
        if 'logged_in' in session:
            flash('You are already logged in', 'danger')
            if session['email'] == 'dankamran1@gmail.com':
                return redirect(url_for('admindashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            return f(*args , **kwargs)
    return wrap





mail = Mail(app)

s = URLSafeTimedSerializer('Thisisasecret!')


class PasswordResetForm(Form):
    password = PasswordField('password', [
    validators.DataRequired(),
    validators.EqualTo('confirm', message='Password does not match!')
    ])
    confirm = PasswordField('Confirm Password')

class ResetEmail(Form):
    email = EmailField('Email', [validators.DataRequired()])

@app.route('/forgot', methods=['GET', 'POST'])
def reset():
    form = ResetEmail(request.form)
    if request.method == 'GET':
        return render_template('forgot.html', form=form)

    email = request.form['email']
    cur = mysql.connection.cursor()
    x = cur.execute("SELECT * FROM parents WHERE email = (%s)", (email,))
    if int(x) == 0:
        flash("Email not found, try again", "danger")
    else:
        token = s.dumps(email, salt='email-confirm')

        msg = Message('Confirm Email', sender='dankamran1@gmail.com', recipients=[email])

        link = url_for('confirm_email', token=token, _external=True)

        msg.body = 'Your link is {}'.format(link)

        mail.send(msg)
        flash('The email you entered is {}. The token is {}'.format(email, token), "success") 
    mysql.connection.commit()
    cur.close()
    return render_template('forgot.html', form=form)


@app.route('/confirm_email/<token>', methods=['GET', 'POST']) 
def confirm_email(token):
    form = PasswordResetForm(request.form)
    form2 = ResetEmail(request.form)
    if request.method == 'POST' and form.validate():
        emails = form2.email.data
        password = sha256_crypt.encrypt(str(form.password.data))
        try:
            s.loads(token, salt='email-confirm',  max_age=3600)
        except SignatureExpired:
            flash("Token expired", "danger")
            return redirect(url_for('index')) 
        cur = mysql.connection.cursor()
        cur.execute("UPDATE PARENTS SET PASSWORD=%s where email=%s", (password, emails))
        mysql.connection.commit()
        cur.close()

        
        flash('Updated Password, Success!', 'success')


        return redirect(url_for('index'))
    return render_template('confirm_email.html' , form=form)


# User Login!
@app.route('/login', methods=['GET', 'POST'])
@Alreadyloggedin
def login():
    global admin
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM parents WHERE email = %s ", [email])
        if result > 0:
            #GET STORED HASH
            data = cur.fetchone()
            password = data['password']
            if sha256_crypt.verify(password_candidate , password):
                session['logged_in'] = True
                session['email'] = email
                flash('You have logged in successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Password / email is not correct try again', 'danger')
                 
        else:
            error = 'Email not found'
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/loginadmin', methods=['GET', 'POST'])
@Alreadyloggedin
def loginadmin():
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM admin WHERE email = %s ", [email])
        if result > 0:
            #GET STORED HASH
            data = cur.fetchone()
            password = data['password']
            if sha256_crypt.verify(password_candidate , password):
                session['logged_in'] = True
                session['email'] = email
                if session['email'] == 'dankamran1@gmail.com':
                    admin = True
                    flash('Welcome admin danish', 'success')
                    return redirect(url_for('admindashboard'))
            else:
                flash('Password is not correct try again', 'danger')
                 
        else:
            error = 'Email not found'
            return render_template('login.html', error=error) 
    return render_template('loginadmin.html')



@app.route('/event/<string:EVENT_ID>/confirmation')
@is_logged_in
def confirmation(EVENT_ID):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM events WHERE EVENT_ID = %s", [EVENT_ID])
    event = cur.fetchone()

    cur.close()
    return render_template('confirmation.html' , event=event)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have suessfully logged out', 'success')
    return redirect(url_for('login'))   

@app.route('/dashboard', methods=['GET'])
@is_logged_in
def dashboard():
    if request.method == 'GET':
     
        cur = mysql.connection.cursor()

   
        cur.execute("SELECT student_id, ygroup FROM STUDENT WHERE PARENT_ID = (SELECT Parent_id FROM PARENTS WHERE email = %s)", [session['email']])
        student_info = cur.fetchone()

        if student_info:
            student_id = student_info['student_id']
            ygroup = student_info['ygroup']

          
            result = cur.execute("""
            SELECT e.* FROM EVENTS e
            LEFT JOIN student_event se ON e.EVENT_ID = se.event_id AND se.student_id = %s
            WHERE (se.applied = 0 OR se.applied IS NULL) AND e.ygroup = %s
            """, (student_id, ygroup))

            events = cur.fetchall()

            if result > 0:
                return render_template('dashboard.html', events=events)
            else:
                msg = 'No events found'
                return render_template('dashboard.html', msg=msg)
        else:
            msg = 'No student or year group found for this parent'
            return render_template('dashboard.html', msg=msg)
        
        cur.close()



@app.route('/admin-dashboard' , methods=['GET'])
@is_logged_in
def admindashboard():
    if request.method == 'GET':
        cur = mysql.connection.cursor()

        result = cur.execute("select * from events" )
        events =cur.fetchall()

        if result >0:
            return render_template('admin-dashboard.html' , events=events)
        else:
            msg = 'No events found'
            return render_template('admin-dashboard.html', msg=msg)
        cur.close()

@app.route('/event/<string:EVENT_ID>/')
@is_logged_in

def event(EVENT_ID):
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM events WHERE EVENT_ID = %s", [EVENT_ID])
    event = cur.fetchone()
    cur.close()
    return render_template('event.html', event=event)


@app.route('/check/<string:EVENT_ID>')
@is_logged_in
def check(EVENT_ID):
    cur = mysql.connection.cursor()

    result = cur.execute("Select tb2.*, tb1.student_id,  tb1.EVENT_ID, tb3.* FROM STUDENT tb2 LEFT JOIN student_event tb1 ON tb2.STUDENT_ID = tb1.student_id  RIGHT JOIN parents tb3 on tb3.PARENT_ID = tb2.PARENT_ID where applied = 0 and EVENT_ID = %s", (EVENT_ID,))
    students = cur.fetchall()
    
    if result > 0:
        return render_template('check.html' , students=students)
    else:
        msg = 'No events found'
        return render_template('check.html', msg=msg)
    

    
    cur.close()

class eventform(Form):
    eventname = StringField('Event', [validators.Length(min=1 , max=50)])
    body = TextAreaField('Body', [validators.Length(min=25)])
    fee = FloatField('Fee')
    time_from = TimeField('Time from')
    time_to = TimeField('Time to')
    event_date = DateField('Event Date', format='%Y-%m-%d')
    creator = StringField('Creator')
    Number_of_days = IntegerField('Number of days')
    event_organiser = StringField('Event organiser', [validators.Length(min=3, max=50)])
    ygroup = SelectField('Year group', choices=['Year 10','Year 11', 'Year 12','Year 13'])
    event_type = SelectField('Event type ', choices=['Parents evening', 'Trip'])

@app.route('/add_event', methods=['GET', 'POST'])
@is_logged_in
def add_event():
    form = eventform(request.form)
    if request.method == 'POST' and form.validate():
        # Extract form data
        eventname = form.eventname.data
        body = form.body.data
        fee = form.fee.data
        time_from = form.time_from.data
        time_to = form.time_to.data
        event_date = form.event_date.data
        creator = form.creator.data
        Number_of_days = form.Number_of_days.data
        event_organiser = form.event_organiser.data
        ygroup = form.ygroup.data
        event_type = form.event_type.data 

        cur = mysql.connection.cursor()
      
        cur.execute("INSERT INTO eventtype(EVENT_TYPE) VALUES(%s)", (event_type,))
        eventtype_id = cur.lastrowid 
        
        cur.execute("""
            INSERT INTO events(
                eventname, body, fee, timefrom, timeto, event_date,
                creator, Number_of_days, ygroup, eventtype_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (eventname, body, fee, time_from, time_to, event_date, session['email'], Number_of_days, ygroup, eventtype_id))
        
        event_id = cur.lastrowid 

        cur.execute("SELECT student_id FROM student WHERE ygroup = %s", [ygroup])
        students = cur.fetchall()
        
     
        for student in students:
            student_id = student['student_id']
            cur.execute("""
                INSERT INTO student_event(student_id, event_id, applied, eventname)
                VALUES (%s, %s, %s, %s)
            """, (student_id, event_id, False, eventname))

        mysql.connection.commit()
        cur.close()

        flash('Event created successfully', 'success')
        return redirect(url_for('admindashboard'))
    else:
      
        flash('Error creating the event. Please check your inputs.', 'danger')

    return render_template('add_event.html', form=form)



@app.route('/edit_event/<string:EVENT_ID>', methods= ['GET', 'POST'])
@is_logged_in
def edit_event(EVENT_ID):
    
    cur = mysql.connection.cursor()

    result = cur.execute("SELECT * FROM events where EVENT_ID  = %s" , [EVENT_ID])
    
    event = cur.fetchone()

    result2= cur.execute("SELECT * FROM EVENT_ORGANISER")

    organiser = cur.fetchone()

    result3 = cur.execute("SELECT * FROM  EVENTTYPE")

    eventtype = cur.fetchone()


    

    form = eventform(request.form)

    form.eventname.data = event['eventname']
    form.body.data = event['body']
    form.fee.data = event['fee']
    form.time_from.data = event['timefrom']
    form.time_to.data = event['timeto']
    form.event_date.data = event['event_date']
    form.creator.data = event['creator']
    form.event_organiser.data = organiser['E_ORGANISER']
    form.Number_of_days.data = event['Number_of_days']
    form.ygroup.data = event['ygroup']
    form.event_type.data = eventtype['event_type']
    

    if request.method == 'POST' and form.validate():
        eventname = request.form['eventname']
        body = request.form['body']
        fee = request.form['fee']
        #time_from = request.form['time_from']
        #time_to = request.form['time_to']
        event_date = request.form['event_date']
        creator = form.creator.data
        organiser = request.form['event_organiser']
        Number_of_days = request.form['Number_of_days']
        ygroup = request.form['ygroup']
        event_type = request.form['event_type']
        



        cur = mysql.connection.cursor()

        cur.execute("UPDATE events SET eventname=%s, body=%s , fee=%s , event_date=%s, creator=%s, Number_of_days=%s, ygroup=%s WHERE EVENT_ID=%s" , (eventname, body, fee, event_date, creator, Number_of_days, ygroup, EVENT_ID))
        cur.execute("UPDATE STUDENT_EVENT set eventname=%s where EVENT_ID=%s", (eventname, EVENT_ID))
        cur.execute("UPDATE EVENT_ORGANISER tb2 LEFT JOIN EVENTS tb1 on tb1.organiser_id = tb2.organiser_id SET e_organiser=%s where EVENT_ID =%s  ", (organiser , EVENT_ID))
        cur.execute("UPDATE eventtype tb2 LEFT JOIN EVENTS tb1 on tb1.eventtype_id = tb2.eventtype_id SET event_type=%s where EVENT_ID =%s  ", (event_type , EVENT_ID))
        mysql.connection.commit()

        cur.close()

        flash('Event updated', 'success')
        return redirect(url_for('admindashboard'))
    return render_template('edit_event.html', form=form)

@app.route('/delete_event/<string:EVENT_ID>', methods= ['POST'] )
@is_logged_in
def delete_event(EVENT_ID):
    cur = mysql.connection.cursor()
    cur.execute("SET FOREIGN_KEY_CHECKS = 0")
    cur.execute("DELETE FROM events WHERE EVENT_ID = %s", [EVENT_ID])
    cur.execute("SET FOREIGN_KEY_CHECKS = 1")
    mysql.connection.commit()
    cur.close()
    flash('Event deleted' , 'success')
    return redirect(url_for('admindashboard'))
@app.route('/event/<string:EVENT_ID>/apply', methods=['POST'])
def apply(EVENT_ID):
    if request.method == 'POST':
      
        cur = mysql.connection.cursor()

     
        cur.execute("SELECT PARENT_ID FROM parents WHERE email = %s", [session['email']])
        parent = cur.fetchone()
        parent_id = parent['PARENT_ID']

        cur.execute("SELECT * FROM events WHERE EVENT_ID = %s", [EVENT_ID])
        event = cur.fetchone()
        event_date = event['event_date']
        eventname = event['eventname']

      
        cur.execute("INSERT INTO parvent(PARENT_ID, EVENT_ID, trip_date, eventname) VALUES (%s, %s, %s, %s)", 
                    (parent_id, EVENT_ID, event_date, eventname))

        
        cur.execute("SELECT STUDENT_ID FROM student WHERE PARENT_ID = %s", (parent_id,))
        student = cur.fetchone()
        student_id = student['STUDENT_ID'] if student else None

        if student_id:
        
            cur.execute("SELECT * FROM student_event WHERE student_id = %s AND event_id = %s", (student_id, EVENT_ID))
            student_event = cur.fetchone()

          
            if student_event:
                cur.execute("UPDATE student_event SET APPLIED = 1 WHERE student_id = %s AND event_id = %s", 
                            (student_id, EVENT_ID))
            else:
                cur.execute("INSERT INTO student_event(student_id, event_id, EVENTNAME, APPLIED) VALUES (%s, %s, %s, 1)", 
                            (student_id, EVENT_ID, eventname))

      
        mysql.connection.commit()

    
        cur.close()

        flash('Event applied', 'success')

  
        return redirect(url_for('dashboard'))

  
    return redirect(url_for('dashboard'))



@app.route('/#')
def hash():
    return render_template('index')



if __name__ == '__main__':
  
    app.run(debug=True, port=5000)
