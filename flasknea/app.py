from functools import wraps
from flask.sessions import NullSession
from wtforms.fields.core import BooleanField, DateField, DecimalField, FloatField, IntegerField, SelectField, SelectMultipleField, TimeField
import smtplib
import ssl
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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

socket.getaddrinfo('127.0.0.1', 5000)

# Adjust MySQL
app.config['STRIPE_PUBLIC_KEY'] = 'pk_live_51JwcNHGRdaLZqAsnxAmAopDuIAaH3KsTgqQUpFpDp7pG4RTYmXsrZ43w3S7hKkcZp21aMIeE3YeAcoTlYDSySeHQ00oCEspLtS'
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

    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    

    return redirect(url_for('login'))


@app.route('/create-checkout-session/<event_id>', methods=['POST'])
def create_checkout_session(event_id):
   
    event = get_event_details(event_id)
    event_price = event['price'] * 100  

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'gbp',
                    'product_data': {
                        'name': event['name'],
                    },
                    'unit_amount': int(event_price),
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('cancel', _external=True),
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403


class RegisterForm(Form):
    firstname = StringField('', [validators.Length(min=1 , max=50)])
    surname = StringField('', [validators.Length(min=1,max=25)])
    number = StringField('', [validators.Length(min=7, max=14)])
    email = EmailField('', [validators.DataRequired(), validators.Email()])
    sfirstname = StringField('', [validators.Length(min=1,max=50)])
    ssurname = StringField('', [validators.Length(min=1,max=50)])
    password = PasswordField('', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Password does not match!')
    ])
    confirm = PasswordField('')
    fgroup = SelectField('', choices=['Mr BotMan' , 'Mr Embassador', 'Mr Mike', 'Miss Puff', 'Miss many'])
    ygroup = SelectField('' , choices=['Year 10', 'Year 11', 'Year 12', 'Year 13'])



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

        mysql.connection.commit()
       
        cur.close()
        
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
            return redirect(url_for('dashboard'))               

        return f(*args , **kwargs)
    return wrap


def isNotAdmin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get('email') != 'dankamran1@gmail.com':
            return f(*args, **kwargs)
        else:
            flash('Access restricted for Admin.', 'danger')
            return redirect(url_for('dashboard'))
    return wrap


def get_event_details(event_id):
  
    cursor = mysql.connection.cursor()
    

    query = "SELECT event_id, name, price FROM events WHERE event_id = %s"
    cursor.execute(query, (event_id,))
    
   
    event = cursor.fetchone()
    cursor.close()
    
  
    if event:

        return {
            'event_id': event[0],
            'name': event[1],
            'price': event[2]
        }
    else:
       
        return None



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
        return render_template('forgot.html', form=form)
    
    if request.method == "POST":
        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        subject = 'Confirm Email'
        body = 'Your link is {}'.format(link)
        sender_email = app.config['MAIL_USERNAME']
        receiver_email = email

    
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        context = ssl.create_default_context()
        if app.config['MAIL_USE_SSL']:
            
                
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'], context=context) as server:

                server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                server.send_message(message)
        else:
                
            with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
                server.ehlo()
                if app.config['MAIL_USE_TLS']:
                    server.starttls()
                    server.ehlo()
                    server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                    server.send_message(message)

        flash('An email has been sent to {}. Please check your email to confirm your account.'.format(email), "success")
        mysql.connection.commit()
        cur.close()
    return render_template('forgot.html', form=form)

@app.route('/confirm_email/<token>', methods=['GET', 'POST']) 
def confirm_email(token):
    form = PasswordResetForm(request.form)
    emailForm = ResetEmail(request.form)
    if request.method == 'POST' and form.validate():
        emails = emailForm.email.data
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

        if email ==  "dankamran1@gmail.com":
            result = cur.execute("SELECT * FROM admin WHERE email = %s ", [email])
        else:
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





@app.route('/event/<string:EVENT_ID>/confirmation')
@is_logged_in
def confirmation(EVENT_ID):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM events WHERE EVENT_ID = %s", [EVENT_ID])
    event = cur.fetchone()

    cur.execute("select tb1.firstname, tb2.sfirstname, tb2.fgroup from parents tb1 left join student tb2 on tb1.parent_id = tb2.parent_id where email = %s ",  [session['email']])
    student_parent = cur.fetchone()

    cur.close()
    return render_template('confirmation.html' , event=event, student_parent=student_parent)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have suessfully logged out', 'success')
    return redirect(url_for('login'))   

from datetime import datetime
from flask import render_template, session, request







@app.route('/dashboard', methods=['GET'])
@is_logged_in
def dashboard():
    cur = mysql.connection.cursor()

 
    delete_parvent_references_query = """
    DELETE FROM parvent 
    WHERE event_id IN (
        SELECT EVENT_ID 
        FROM EVENTS 
        WHERE DATE_ADD(date_created, INTERVAL number_of_days DAY) < NOW()
    )
    """
    cur.execute(delete_parvent_references_query)

 
    delete_student_event_references_query = """
    DELETE FROM student_event 
    WHERE event_id IN (
        SELECT EVENT_ID 
        FROM EVENTS 
        WHERE DATE_ADD(date_created, INTERVAL number_of_days DAY) < NOW()
    )
    """
    cur.execute(delete_student_event_references_query)

   
    delete_events_query = """
    DELETE FROM EVENTS 
    WHERE DATE_ADD(date_created, INTERVAL number_of_days DAY) < NOW()
    """
    cur.execute(delete_events_query)

    if session['email'].lower() == 'dankamran1@gmail.com':
        cur.execute("SELECT *, DATEDIFF(event_date, CURDATE()) AS deadline FROM EVENTS;")
        allevents = cur.fetchall()
        cur.close()
        return render_template('dashboard.html', events=allevents)
    else:
        cur.execute("SELECT student_id, ygroup FROM STUDENT WHERE PARENT_ID = (SELECT Parent_id FROM PARENTS WHERE email = %s)", [session['email']])
        student_info = cur.fetchone()

        if student_info:
            student_id = student_info['student_id']
            ygroup = student_info['ygroup']

            result = cur.execute("""
                SELECT e.*, DATEDIFF(e.event_date, CURDATE()) AS deadline FROM EVENTS e
                LEFT JOIN student_event se ON e.EVENT_ID = se.event_id AND se.student_id = %s
                WHERE (se.applied = 0 OR se.applied IS NULL) AND e.ygroup = %s
            """, (student_id, ygroup))

            events = cur.fetchall()
            cur.close()

            if result > 0:
                return render_template('dashboard.html', events=events)
            else:
                msg = 'No events found'
                return render_template('dashboard.html', msg=msg)
        else:
            msg = 'No student or year group found for this parent'
            return render_template('dashboard.html', msg=msg)


@app.route('/event/<string:EVENT_ID>/')
@is_logged_in
@isNotAdmin

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

 
    cur.execute("SELECT ygroup FROM events WHERE EVENT_ID = %s", [EVENT_ID])
    event_ygroup = cur.fetchone()

    if event_ygroup:
       
        result = cur.execute("""
            SELECT s.*, s.student_id, se.EVENT_ID, p.*
            FROM STUDENT s
            JOIN parents p ON s.PARENT_ID = p.PARENT_ID
            LEFT JOIN student_event se ON s.STUDENT_ID = se.student_id AND se.EVENT_ID = %s
            WHERE (se.applied = 0 OR se.applied IS NULL) AND s.ygroup = %s
        """, (EVENT_ID, event_ygroup['ygroup']))
        students = cur.fetchall()

        if result > 0:
            return render_template('check.html', students=students)
        else:
            msg = 'No unapplied students found in this year group for the event'
            return render_template('check.html', msg=msg)
    else:
        msg = 'Event year group not found'
        return render_template('check.html', msg=msg)

    cur.close()

    
class eventform(Form):
    eventname = StringField('Event', [validators.Length(min=1 , max=50)])
    body = TextAreaField('Body', [validators.Length(min=25)])
    fee = FloatField('Fee')
    time_from = TimeField('Time from', format='%H:%M')
    time_to = TimeField('Time to', format='%H:%M')
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
        return redirect(url_for('dashboard'))
    elif not request.method:
      
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
        return redirect(url_for('dashboard'))
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
    return redirect(url_for('dashboard'))
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
