from flask import render_template, flash, redirect, url_for, request, Flask, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user, login_required    
from werkzeug.urls import url_parse
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import Form, TextField, PasswordField, validators, SubmitField, \
        RadioField, StringField, TextAreaField, DateTimeField, SelectField, BooleanField, IntegerField, HiddenField
from wtforms.fields.html5 import EmailField 
from wtforms.validators import ValidationError, DataRequired, EqualTo, Email
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from passlib.context import CryptContext
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, Signer
import random
import sys, pymysql, getpass, os
import datetime
import flask_gravatar
import urllib, hashlib
from flask_avatars import Avatars
from flask_wtf.file import FileField, FileAllowed, FileRequired


#######FORMS##############
# Login form (subclassed from FlaskForm)
class LoginForm(FlaskForm):
    user_email = StringField('', validators=[DataRequired(), Email(message="Invalid email")], render_kw={"placeholder": "Enter Email"})
    password = PasswordField('', validators=[DataRequired()], render_kw={"placeholder": "Enter Password"})
    submit = SubmitField('')

class RegisterForm(FlaskForm):
    form_email = EmailField('Enter email', validators=[DataRequired(), Email()])
    form_first_name = StringField('Enter First Name', validators=[DataRequired()])
    form_last_name = StringField('Enter Last Name', validators=[DataRequired()])
    form_major = StringField('Major', validators=[DataRequired()])
    form_pass = PasswordField('Enter password', validators=[DataRequired(), EqualTo('form_confirm', message="Passwords Must Match")])
    form_confirm = PasswordField('Confirm password', validators=[DataRequired()])
    form_submit = SubmitField(validators=[DataRequired()])

class HomeForm(FlaskForm):
    search = TextField('Search', validators=[DataRequired()])
    submit = SubmitField('Search')

def event_add(primary_tags):
    class eventAdd(FlaskForm):
        name = StringField("Enter name of event: ", validators =[DataRequired()])
        location = StringField("Enter location of event: ", validators = [DataRequired()])
        starttime = DateTimeField("Start time of event: (YYYY-MM-DD hh:mm:ss)",validators =[DataRequired()])
        endtime = DateTimeField("End time of event: (YYYY-MM-DD hh:mm:ss)", validators =[DataRequired()])
        max_attendees  = IntegerField("Maximum Attendees: ", validators =[])
        primary_tag = SelectField('Select primary tag:', \
            choices=primary_tags, default=primary_tags[0][0])
        secondary_tags = StringField('Enter secondary tags (comma separated):')
        description = TextAreaField("Please type info about the event")
        is_private = BooleanField("Private Event", validators=[])
        submit = SubmitField('Submit', render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})
    return eventAdd()

class ProfileEdit(FlaskForm):
    first_name = StringField('Enter First Name')
    last_name = StringField('Enter Last Name')
    birthday = StringField('Enter Birthday')
    user_bio = StringField('Enter Bio')
    major = StringField('Major')
    submit = SubmitField('Submit')

def interest_group_form(primary_tags):
    class InterestGroupForm(FlaskForm):
        group_name = StringField('Enter group name:', validators=[DataRequired()])
        group_description = StringField('Enter group description:', validators=[DataRequired()])
        group_primary_tag = SelectField('Select primary tag:', \
            choices=primary_tags, default=primary_tags[0][0])
        group_secondary_tags = StringField('Enter secondary tags (comma separated):')
        private = BooleanField('Private group?')
        submit = SubmitField('Submit')
    return InterestGroupForm()

class SearchForm(Form):
	search = StringField('')

class BanForm(FlaskForm):
    ban_email = StringField("Enter Users Email to Ban or Un-Ban")
    submit1 = SubmitField('Submit', render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})

class AddAdminForm(FlaskForm):
    add_admin = StringField("Enter Email to Make Admin")
    submit2 = SubmitField('Submit', render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})

class AdminSearchForm(FlaskForm):
    search_user = StringField("Enter User Email to Look Up")
    submit3 = SubmitField('Submit', render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})

class EventPage(FlaskForm):
    submit = SubmitField('Join', render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})

class GroupPage(FlaskForm):
    submit = SubmitField('Join', render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})

class ForgotPassForm(FlaskForm):
    forgot_email = StringField("Enter Your Email Address", validators=[DataRequired()])
    submit = SubmitField("Submit")

class ResetPassForm(FlaskForm):
    reset_pswd = PasswordField("Enter Your New Password", validators=[DataRequired(), EqualTo('reset_confirm', message="Passwords Must Match")])
    reset_confirm = PasswordField("Re-Enter Your New Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

class ConfirmEmailForm(FlaskForm):
    submit = SubmitField('Confirm Email')

class CommentForm(FlaskForm):
    comment = StringField(validators=[DataRequired()])
    post = SubmitField('Post')

class LeaveButton(FlaskForm):
    leave = SubmitField('Leave', render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})

class RemoveForm(FlaskForm):
    remove = IntegerField("Enter ID of Event/Group You'd Like to Delete", validators=[DataRequired()])
    submit = SubmitField('Remove', render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})

class UploadAvatarForm(FlaskForm):
    image = FileField('Upload (<=3M)', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'png'], 'The file format should be .jpg or .png.')])
    submit = SubmitField()

class DeleteForm(FlaskForm):
    submit2 = SubmitField("Delete", render_kw={'style':'background-color:#00A2CE; color: #FFFFFF'})

#############

# User class, subclassed from UserMixin for convenience.  UserMixin
# provides attributes to manage user (e.g. authenticated).  The User
# class defines a "role" attribute that represents the user role (e.g.  Regular
# user or admin)
class User(UserMixin):
    def __init__(self, username, password, role):
        self.id = username
        # hash the password and output it to stderr
        self.pass_hash = password
        self.role = role

#FLASK APPLICATION
# creating the Flask app object and login manager
app = Flask(__name__)
avatars = Avatars(app) #Profile Image
app.db = None
app.config['SECRET_KEY'] = 'a hard to guess string'
bootstrap = Bootstrap(app)
moment = Moment(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
user_db = {}

#Flask Mail Configuration
app.config['DEBUG'] = True
app.config['TESTING'] =  False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEBUG'] = True
app.config['MAIL_USERNAME'] = 'noreplyscsu@gmail.com'
app.config['MAIL_PASSWORD'] = 'piratebay1!'
app.config['MAIL_DEFAULT_SENDER'] = 'noreplyscsu@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
mail = Mail(app)


#Connect to database
def connect_db():
    if not app.db:
        #db_IP = input('Input IP address of DB instance: ')
        app.db = pymysql.connect('35.245.180.101', 'root', 'PirateBay', 'SCSU')
    else:
        print('Already connected', file=sys.stderr)

#Password hashing
pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
)

def encrypt_password(password):
    return pwd_context.encrypt(password)


def check_encrypted_password(password, hashed):
    return pwd_context.verify(password, hashed)


# Returns True if logged in user has "admin" role, False otherwise.
def is_admin():

    if not app.db:
       connect_db()

    g.user = current_user.get_id()
    c = app.db.cursor()
    c.execute("SELECT isADMIN FROM USERS WHERE EMAIL='{0}'".format(g.user))
    admin = c.fetchall()
    isAdmin = admin[0][0]
    
    if isAdmin == True:
        return True
    else:
        return False 

# Login manager uses this function to manage user sessions.
# Function does a lookup by id and returns the User object if
# it exists, None otherwise.
@login_manager.user_loader
def load_user(id):
    return user_db.get(id)

@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', current_user.id)

# This mimics a situation where a non-admin user attempts to access
# an admin-only area.  @login_required ensures that only authenticated
# users may access this route.
@app.route('/admin_only', methods=['GET','POST'])
@login_required
def admin_only():
    if not app.db:
        connect_db()

    c = app.db.cursor()
    c.execute("SELECT EMAIL, FIRST_NAME, LAST_NAME, isADMIN, isBANNED FROM USERS")
    users = c.fetchall()

    all_users = []

    for user in users:
        user_email = user[0]
        user_fname = user[1]
        user_lname = user[2]
        user_admin = user[3]
        user_banned = user[4]

        if user_admin == True:
            user_admin = 'Yes'
        else:
            user_admin = 'No'

        if user_banned == True:
            user_banned = 'Yes'
        else:
            user_banned = 'No'

        all_users.append([user_email, user_fname, user_lname, user_admin, user_banned])


    banform = BanForm()
    ban_email = None
    g.user = current_user.get_id()
  
    if banform.submit1.data and banform.validate():
        ban_email = banform.ban_email.data
        c.execute("SELECT isADMIN, isBANNED FROM USERS WHERE EMAIL='{0}'".format(ban_email))
        banned = c.fetchall()
        anAdmin = banned[0][0]
        isBanned = banned[0][1] 

        if g.user == ban_email:
            flash("You Cannot Ban Yourself")
            return redirect(url_for("admin_only"))
        
        if anAdmin == True:
            flash("You Cannot Ban Another Admin")
            return redirect(url_for("admin_only"))
           
        if isBanned == False:
            c.execute("UPDATE USERS SET isBANNED = TRUE WHERE EMAIL = '{0}'".format(ban_email))
            app.db.commit()
            msg = Message('Your Account Has Been Banned', recipients=[ban_email])
            msgBody = ('Due to Several Complaints From the Community,' +
                       ' Your Account Has Been Looked Into and the Decision' +
                       ' Has Been Made to Permanently Ban Your Account.' +
                       ' Contact Us if You Have Any Questions')
            msg.body = '{}'.format(msgBody)
            mail.send(msg)
            return redirect(url_for("admin_only"))
        else:
            c.execute("UPDATE USERS SET isBANNED = False WHERE EMAIL = '{0}'".format(ban_email))
            app.db.commit()
            msg = Message('Your Account Has Been UnBanned', recipients=[ban_email])
            msgBody = (' Upon Further Investigation, Your Account Has Been' +
                       ' Has UnBanned. Please Make Sure to Follow Community' +
                       ' Standards in the Future')
            msg.body = '{}'.format(msgBody)
            mail.send(msg)
            return redirect(url_for("admin_only"))
        banform = BanForm(formdata=None)
       

    adminform = AddAdminForm()
    add_admin = None

    if adminform.submit2.data and adminform.validate():
        add_admin = adminform.add_admin.data
        c.execute("SELECT isADMIN FROM USERS WHERE EMAIL='{0}'".format(add_admin))
        check_admin = c.fetchall()
        admin_value =  check_admin[0][0]
    
        if admin_value == True:
            flash("User is Already an Admin")
            return redirect(url_for("admin_only"))
        else:
            c.execute("UPDATE USERS SET isADMIN = TRUE WHERE EMAIL = '{0}'".format(add_admin))
            app.db.commit()
            msg = Message('Your Account Has Been Made an Admin', recipients=[add_admin])
            msgBody = ('You Have Upheld Community Standards Very Well And' +
                       ' A Decision Has Been Made to Make Your Account an Admin.' +
                       ' Please Do Not Abuse These Privledges or Your Status Will Be Removed.' +
                       ' If You Have Any Questions, Feel Free to Contact Us.' +
                       ' We Look Forward to Seeing You Help Improve Our Communtity \n -PirateBay  ')
            msg.body = '{}'.format(msgBody)
            mail.send(msg)
            return redirect(url_for("admin_only"))
        adminform = AddAdminForm(formdata=None)


    searchform = AdminSearchForm()
    search_user = None
    message = "User Does Not Exist"

    if searchform.submit3.data and searchform.validate():
        search_user = searchform.search_user.data
        c.execute("SELECT EMAIL, FIRST_NAME, LAST_NAME, isADMIN, isBANNED FROM USERS WHERE EMAIL = '{0}'".format(search_user))
        user_search = c.fetchall()

        specific_user = []

        for users_info in user_search:
            specific_email = users_info[0]
            specific_fname = users_info[1]
            specific_lname = users_info[2]
            specific_admin = users_info[3]
            specific_banned = users_info[4]

        if not user_search:
            flash(message)
            return redirect(url_for('admin_only'))

        if specific_admin == True:
            specific_admin = 'Yes'
        else:
            specific_admin = 'No'

        if specific_banned == True:
            specific_banned = 'Yes'
        else:
            specific_banned = 'No'

        specific_user.append([specific_email, specific_fname, specific_lname, specific_admin, specific_banned])

        searchform = AdminSearchForm(formdata=None)

        return render_template('admin.html',all_users=all_users, spUser=specific_user, banform=banform, adminform=adminform, searchform=searchform)

    # determine if current user is admin
    if is_admin():
        return render_template('admin.html', all_users=all_users,banform=banform, adminform=adminform, searchform=searchform)
    else:
        return render_template('unauthorized.html')

#ALLOWS FOR ADMIN TO DELETE EVENTs
@app.route('/admin_events', methods=['GET','POST'])
@login_required
def adminEvents():
    if is_admin():
        if not app.db:
            connect_db()

        all_events = []
        c = app.db.cursor()
        c.execute("SELECT * FROM EVENTS")
        events = c.fetchall()

        for event in events:
            event_id = event[0]
            c.execute("SELECT USERS.FIRST_NAME, USERS.LAST_NAME, USERS.EMAIL FROM USERS INNER JOIN EVENTS ON USERS.USER_ID=EVENTS.CREATOR_ID AND EVENTS.EVENT_ID={0}".format(event_id))
            event_coordinator = c.fetchall()
            coordinator_name = event_coordinator[0][0] + ' ' + event_coordinator[0][1]
            event_name = event[1]
            location = event[2]
            creator_id = coordinator_name

            all_events.append([event_id, event_name, location, creator_id])

            form = RemoveForm()
            remove = None
            message="Event Does Not Exist"

            if form.validate_on_submit():
                remove = form.remove.data
                c.execute("SELECT * FROM EVENTS WHERE EVENT_ID={0}".format(remove))
                check = c.fetchall()
                if not check:
                    flash(message)
                    return redirect(url_for('adminEvents'))

                else:
                    if check[0][9] == None:
                        c.execute("DELETE FROM EVENT_TAGS WHERE EVENT_ID = {0}".format(remove))
                        c.execute("DELETE FROM COMMENTS WHERE COMMENT_ID = {0}".format(remove))
                        c.execute("DELETE FROM EVENT_ATTENDEES WHERE EVENT_ID = {0}".format(remove))
                        c.execute("DELETE FROM EVENTS WHERE EVENT_ID = {0}".format(remove))
                        app.db.commit()
                        form = RemoveForm(formdata=None)
                    
                        return redirect(url_for('adminEvents'))

                    else:
                        c.execute("DELETE FROM EVENT_TAGS WHERE EVENT_ID = {0}".format(remove))
                        c.execute("DELETE FROM COMMENTS WHERE COMMENT_ID = {0}".format(remove))
                        c.execute("DELETE FROM EVENT_ATTENDEES WHERE EVENT_ID = {0}".format(remove))
                        c.execute("DELETE FROM COMMENTS_GROUPS WHERE COMMENT_ID = {0}".format(check[0][9]))
                        c.execute("DELETE FROM EVENTS WHERE GROUP_ID = {0}".format(check[0][9]))
                        c.execute("DELETE FROM EVENTS WHERE EVENT_ID = {0}".format(remove))
                        app.db.commit()
                        form = RemoveForm(formdata=None)
                    
                        return redirect(url_for('adminEvents'))

        return render_template('adminevents.html', all_events=all_events, form=form)
    else:
        return render_template('unauthorized.html')


#ALLOWS FOR ADMINS TO DELETE GROUPS
@app.route('/admin_groups', methods=['GET','POST'])
@login_required
def adminGroups():
    if is_admin():
        if not app.db:
            connect_db()

        c = app.db.cursor()
        all_groups = []
        c = app.db.cursor()
        c.execute("SELECT * FROM GROUPS")
        groups = c.fetchall()

        for group in groups:
            group_id = group[0]
            group_name = group[1]
            group_owner_id = group[2]
            c.execute('SELECT FIRST_NAME, LAST_NAME FROM USERS WHERE USER_ID={0}'.format(group_owner_id))
            owner_name = c.fetchall()
            group_owner_id = owner_name[0][0] + ' ' + owner_name[0][1]

            all_groups.append([group_id, group_name, group_owner_id])

            form = RemoveForm()
            remove = None
            message="Group Does Not Exist"

            if form.validate_on_submit():
                remove = form.remove.data
                c.execute("SELECT * FROM GROUPS WHERE GROUP_ID={0}".format(remove))
                check = c.fetchall()
                if not check:
                    flash(message)
                    return redirect(url_for('adminGroups'))
                else:
                    c.execute("DELETE FROM COMMENTS_GROUPS WHERE COMMENT_ID = {0}".format(remove))
                    c.execute("DELETE FROM GROUP_TAGS WHERE GROUP_ID = {0}".format(remove))
                    c.execute("DELETE FROM GROUP_MEMBERS WHERE GROUP_ID = {0}".format(remove))
                    c.execute("DELETE FROM GROUPS WHERE GROUP_ID = {0}".format(remove))
                    app.db.commit()
                    form = RemoveForm(formdata=None)
                    
                
                    return redirect(url_for('adminGroups'))

        return render_template('admingroups.html', all_groups=all_groups, form=form)
    else:
        return render_template('unauthorized.html')

#HOME
@app.route('/home', methods=['GET', 'POST'])
def home():
    events = upcoming_events()
    groups = newest_groups()
    users = newest_users()
    my_events = my_events_home()
    search = SearchForm(request.form)
    if request.method == 'POST':
        return search_result(search)
    return render_template('home.html', name=current_user.id, event_data=events, group_data=groups, user_data=users, myevents=my_events, form=search)

#Gets event information based on ID
def get_event(id):
        if not app.db:
                connect_db()
        c = app.db.cursor()

        c.execute("SELECT EVENT_NAME, LOCATION, START_TIME, END_TIME, DESCRIPTION, EVENT_ID FROM EVENTS WHERE EVENT_ID = {0}".format(event_id))

        event_data = c.fetchall()
        event_name = event_data[0][0]
        event_location = event_data[0][1]
        event_start_time = dateconverter(str(event_data[0][2]))
        event_end_time = dateconverter(str(event_data[0][3]))
        event_details = event_data[0][4]
        event_id = event_data[0][5]

        event = [event_name, event_location, event_start_time, event_end_time, event_details, event_id]

        return event

#IF A ROUTE WAS SUCCESSFUL, RETURN THIS. USED TO CHECK CODE
@app.route('/success')
def success():
    return render_template('success.html')

#GO TO A USER'S PROFILE
@app.route('/profile/<username>')
@login_required
def profile(username):
    if not app.db:
        connect_db()

    c = app.db.cursor()


    c.execute("SELECT FIRST_NAME, LAST_NAME, EMAIL, USER_BIO, BIRTH_DATE, MAJOR FROM USERS WHERE EMAIL = '{0}@southernct.edu'".format(username))
    results = c.fetchall()

    c.execute("SELECT USER_ID FROM USERS WHERE EMAIL='{0}'".format(results[0][2]))
    user_id = c.fetchall()

    c.execute("SELECT EVENT_ID, EVENT_NAME FROM EVENTS WHERE CREATOR_ID = {0}".format(user_id[0][0]))
    event_info = c.fetchall()

    user_info = []
    
    for info in results:
        for i in info:
            user_info.append(i)
    
    #Convert lists into a dictionary
    user_details = ['First Name', 'Last Name', 'Email', 'Bio', 'Birthday', 'Major']
    dictionary = dict(zip(user_details, user_info))
    try:
        dictionary['Birthday'] = dictionary['Birthday'].strftime('%m/%d/%Y')
    except:
        pass

    default = "https://www.gravatar.com/avatar/HASH"
    size = 80
 
    avatar_hash = hashlib.md5(dictionary['Email'].lower().encode('utf-8')).hexdigest()

    return render_template('profile.html', user=username, data=dictionary, email_hash=avatar_hash, event_data=event_info)

    c.execute("SELECT FIRST_NAME, LAST_NAME, EMAIL, MAJOR FROM USERS WHERE email = '{0}@southernct.edu'".format(username))
    results = c.fetchall()

    first_name = results[0][0]
    last_name = results[0][1]
    email = results[0][2]
    major = results[0][3]
    
    user_info = [first_name, last_name, email, major]
    return render_template('profile.html', user=username, data=user_info)

#VISIT YOUR OWN PROFILE 
@app.route('/myprofile/',  methods=['GET', 'POST'])
@login_required
def myprofile():
    if not app.db:
        connect_db()

    g.user = current_user.get_id()
    c = app.db.cursor()

    c.execute("SELECT FIRST_NAME, LAST_NAME, EMAIL, USER_BIO, BIRTH_DATE, MAJOR, CONFIRM_TIME FROM USERS WHERE email = '{0}'".format(g.user))

    results = c.fetchall()

    c.execute("SELECT USER_ID FROM USERS WHERE EMAIL='{0}'".format(g.user))
    user_id = c.fetchall()

    c.execute("SELECT EVENT_ID, EVENT_NAME FROM EVENTS WHERE CREATOR_ID = {0}".format(user_id[0][0]))
    event_info = c.fetchall()

    email = g.user
    default = "https://www.gravatar.com/avatar/HASH"
    size = 80
    user_info = []
    avatar_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()

    for info in results:
        for i in info:
            user_info.append(i)
    
    #Convert lists into a dictionary
    user_details = ['First Name', 'Last Name', 'Email', 'Bio', 'Birthday', 'Major', 'Confirm Time']
    dictionary = dict(zip(user_details, user_info))

    try:
        dictionary['Birthday'] = dictionary['Birthday'].strftime('%m/%d/%Y')
        dictionary['Confirm Time'] = dictionary['Confirm Time'].strftime('%m/%d/%Y')
    except:
        pass

    return render_template('profile.html', data=dictionary, email_hash=avatar_hash, event_data=event_info)

#Edits user profile. If user doesn't type anything into form, returns empty string
@app.route('/editprofile/', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if not app.db:
        connect_db()

    c = app.db.cursor()
    g.user = current_user.get_id()
    form = ProfileEdit()

    if form.validate_on_submit():
        first_name = ('FIRST_NAME', form.first_name.data)
        last_name = ('LAST_NAME', form.last_name.data)
        major = ('MAJOR', form.major.data)
        user_bio = ('USER_BIO', form.user_bio.data)
        birth_date = ('BIRTH_DATE', form.birthday.data)
        submit = form.submit

        user_tuple_list = [first_name, last_name, user_bio, birth_date, major]
        
        print(user_tuple_list, file=sys.stderr)
        for info in user_tuple_list:
            if info[1] != '':    
                c.execute("UPDATE USERS SET {0} = '{1}' WHERE EMAIL = '{2}'".format(info[0], info[1], g.user))
                app.db.commit()

        form = ProfileEdit(formdata=None)

    return render_template('editprofile.html', form=form)

#LOGIN FOR APPLICATION
@app.route('/login', methods=['GET', 'POST'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if not app.db:
        connect_db()

    c = app.db.cursor()
    form = LoginForm()
    error = None


    if form.validate_on_submit():
        user_email = form.user_email.data
        username_split = user_email.split('@')
        if username_split[1].lower() != 'southernct.edu':
            error = "Must be @southernct.edu email"
            return render_template('login.html', title='Sign In', form=form, error=error)

        else:
            user = User(form.user_email.data, form.password.data, 'user')
            c.execute("SELECT PASS_HASH,isADMIN,isBANNED,EMAIL_CONFIRM FROM USERS WHERE EMAIL='{0}'".format(form.user_email.data))
            user_info = c.fetchall()
            check_banned = user_info[0][2]
            check_confirmed = user_info[0][3]

            valid_password = check_encrypted_password(form.password.data, user_info[0][0])

            if check_banned == True:
                return render_template('login.html',form=form, check_banned=check_banned)

            if check_confirmed == False:
                return render_template('emailconfirm.html')

            if user is None or not valid_password:
                error = "Invalid username or password"
                return render_template('login.html', title='Sign In', form=form, error=error)

            else:
                user_db['{0}'.format(form.user_email.data)] = user
                login_user(user)
                return redirect(url_for('home'))

    return render_template('login.html', title='Sign In', form=form)

s = URLSafeTimedSerializer("Thisisasecret")

#REGISTRATION FOR APPLICATION
@app.route('/register/', methods=['GET', 'POST'])
def register():
    if not app.db:
        connect_db()

    c = app.db.cursor()
    email = None
    pwd = None
    f_name = None
    l_name = None
    major = None
    form = RegisterForm()
    error = None
    temp = "temp"

    if form.validate_on_submit():
        email = form.form_email.data
        pwd = encrypt_password(form.form_pass.data)
        f_name = form.form_first_name.data
        l_name = form.form_last_name.data
        major = form.form_major.data
        email_split = email.split('@')
        if email_split[1] != 'southernct.edu':
            error = 'Must be @southernct.edu Email'
            form = RegisterForm(formdata=None)
            return render_template('register.html', form=form, error=error)
        else:
            check_email_duplicate = c.execute("SELECT EMAIL FROM USERS WHERE EMAIL='{0}'".format(form.form_email.data))
            if check_email_duplicate != 0:
                error = 'Email already in use'
                return render_template('register.html', form=form, error=error)

            else:
                user_db[temp] = form.form_email.data #Temp Store User Email for Confirm Email
                c.execute("INSERT INTO USERS (FIRST_NAME, LAST_NAME, EMAIL, PASS_HASH, isADMIN, MAJOR) VALUES('{0}', '{1}', '{2}', '{3}', 0, '{4}')".format(f_name, l_name, email, pwd, major))
                app.db.commit()
                token = s.dumps(email, salt='email-confirm')
                msg = Message('Confirm Email', recipients=[email])
                link = url_for('confirm_email', token=token, _external=True)
                msg.body = "Your Link is {}".format(link)
                mail.send(msg)
                return render_template('register_success.html')
    return render_template('register.html', form=form)

u_email = {}
#FORGOT PASSWORD
@app.route('/forgot_pass/', methods=['GET', 'POST'])
def forgot_pass():
    if not app.db:
        connect_db()

    c = app.db.cursor()

    form = ForgotPassForm()
    forgot_email = None
    temp = "temp"
    if form.validate_on_submit():
        forgot_email = form.forgot_email.data
        token2 = s.dumps(forgot_email, salt='reset-email')
        msg2 = Message('Reset Email', recipients=[forgot_email])
        link2 = url_for('reset_pass', token2=token2, _external=True)
        msg2.body = "Your Link is {}".format(link2)
        mail.send(msg2)
        u_email[temp] = form.forgot_email.data
        form = ForgotPassForm(formdata=None)
        return render_template('forgotpass.html', form=form, message="Email Successfully Sent")
    return render_template('forgotpass.html', form=form)

#EMAIL CONFIRMATION
@app.route('/confirm_email/<token>', methods=['GET', 'POST'])
def confirm_email(token):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    form = ConfirmEmailForm()

    e_user = user_db['temp']
    c.execute("SELECT EMAIL_CONFIRM, CONFIRM_TIME FROM USERS WHERE EMAIL = '{0}'".format(e_user))
    confirm = c.fetchall()

    try:
        email = s.loads(token, salt='email-confirm', max_age=86400)
        
    except SignatureExpired:
        return render_template('email_expired.html')
        
    if form.validate_on_submit():
        if confirm[0][0] == False:
            current_time = str(datetime.datetime.now())
            current_time = current_time.split('.')
            c.execute("UPDATE USERS SET EMAIL_CONFIRM = TRUE, CONFIRM_TIME = '{0}' WHERE EMAIL='{1}'".format(current_time[0], e_user))
            app.db.commit()
            return render_template('confirm.html', form=form, message="Email Successfully Confirmed")
        else:
            return render_template('already_confirmed.html')

    return render_template('confirm.html', form=form, email=email)

#PASSWORD RESET
@app.route('/reset_pass/<token2>', methods=['GET', 'POST'])
def reset_pass(token2):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    comp_email = u_email['temp']
    form = ResetPassForm()
    reset_pswd = None
    reset_confirm = None

    try:
        reset = s.loads(token2, salt='reset-email', max_age=86400)
            
    except SignatureExpired:
        return render_template('email_expired.html')
        
    if form.validate_on_submit():
        reset_pswd = encrypt_password(form.reset_pswd.data)
        c.execute("UPDATE USERS SET PASS_HASH = '{0}' WHERE EMAIL = '{1}'".format(reset_pswd, comp_email))
        app.db.commit()
        form = ResetPassForm(formdata=None)
        return render_template("reset_pass.html", form=form, message="Password Successfully Reset")

    return render_template("reset_pass.html", form=form)

#ADD EVENT TO DATABASE
@app.route('/eventadd', methods=['GET', 'POST'])
@login_required
def createEvent():
        if not app.db:
                connect_db()

        c = app.db.cursor()
        primary_tags = get_primary_tags()
        form = event_add(primary_tags)
        user = None
        
        if form.validate_on_submit():
                name = form.name.data
                location = form.location.data
                start = form.starttime.data
                end = form.endtime.data
                primary = form.primary_tag.data
                secondaries = form.secondary_tags.data
                secondaries = separate_tags(secondaries)
                description = form.description.data
                max_attendees = form.max_attendees.data
                private = form.is_private.data
                g.user = current_user.get_id()
                c.execute("SELECT USER_ID from USERS WHERE EMAIL='{0}'".format(g.user))
                user_info = c.fetchall()
                user_id = user_info[0][0]
                print(user_info, file=sys.stderr)
                c.execute('INSERT INTO EVENTS (EVENT_NAME, LOCATION, START_TIME, END_TIME, \
                        CREATOR_ID, DESCRIPTION, MAX, PRIVATE) VALUES ("{}","{}","{}","{}", {}, "{}", {}, {});'. format(name, \
                        location, start, end, user_id, description, max_attendees, private))
                event_id = get_values('SELECT EVENT_ID from EVENTS where EVENT_NAME="{}";'.format(name))
                event_id = event_id[0][0]
                change_values('INSERT INTO EVENT_TAGS VALUES({},{})'.format(event_id, primary))
                change_values('INSERT INTO EVENT_ATTENDEES VALUES({},{});'.format(event_id, user_id))
                if secondaries:
                        for secondary_tag in secondaries:
                                if not get_values('SELECT TAG_TITLE FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag)):
                                        change_values('INSERT INTO TAGS(TAG_TITLE, isPRIMARY) VALUES("{}", 0);'.format(secondary_tag))
                                        secondary_tag_ID = get_values('SELECT TAG_ID FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag))
                                        change_values('INSERT INTO EVENT_TAGS VALUES({}, {});'.format(event_id, secondary_tag_ID[0][0]))
                app.db.commit()
                return redirect(url_for('my_events'))
        return render_template('eventadd.html', form=form)

#ADD AN EVENT FOR A GROUP
@app.route('/groupevents/<group_id>', methods=['GET', 'POST'])
@login_required
def group_event(group_id):
        if not app.db:
                connect_db()

        c = app.db.cursor()
        primary_tags = get_primary_tags()
        form = event_add(primary_tags)
        user = None
        print(group_id, file=sys.stderr)
        
        if form.validate_on_submit():
                name = form.name.data
                location = form.location.data
                start = form.starttime.data
                end = form.endtime.data
                primary = form.primary_tag.data
                secondaries = form.secondary_tags.data
                secondaries = separate_tags(secondaries)
                description = form.description.data
                max_attendees = form.max_attendees.data
                private = form.is_private.data
                g.user = current_user.get_id()
                c.execute("SELECT USER_ID from USERS WHERE EMAIL='{0}'".format(g.user))
                user_info = c.fetchall()
                user_id = user_info[0][0]
                print('hi', file=sys.stderr)
                c.execute('INSERT INTO EVENTS (EVENT_NAME, LOCATION, START_TIME, END_TIME, \
                        CREATOR_ID, DESCRIPTION, MAX, PRIVATE, GROUP_ID) VALUES ("{}","{}","{}","{}", {}, "{}", {}, {}, {});'. format(name, \
                        location, start, end, user_id, description, max_attendees, private, group_id))
                event_id = get_values('SELECT EVENT_ID from EVENTS where EVENT_NAME="{}";'.format(name))
                event_id = event_id[0][0]
                change_values('INSERT INTO EVENT_TAGS VALUES({},{})'.format(event_id, primary))
                change_values('INSERT INTO EVENT_ATTENDEES VALUES({},{});'.format(event_id, user_id))
                if secondaries:
                        for secondary_tag in secondaries:
                                if not get_values('SELECT TAG_TITLE FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag)):
                                        change_values('INSERT INTO TAGS(TAG_TITLE, isPRIMARY) VALUES("{}", 0);'.format(secondary_tag))
                                        secondary_tag_ID = get_values('SELECT TAG_ID FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag))
                                        change_values('INSERT INTO EVENT_TAGS VALUES({}, {});'.format(event_id, secondary_tag_ID[0][0]))
                app.db.commit()
                return redirect(url_for('my_groups'))
        
        return render_template('groupevent.html', form=form, group_id=group_id)

#GO TO AN EVENT ASSOCIATED BASED ON ITS ID
@app.route('/event/<event_id>', methods=['GET', 'POST'])
@login_required
def event_page(event_id):
    if not app.db:
        connect_db()

    button=False
    
    if is_event_owner(event_id):
        button=True  
    

    form = EventPage()
    leave_button = LeaveButton()     

    c = app.db.cursor()
    c.execute("SELECT EVENT_NAME, LOCATION, START_TIME, END_TIME, DESCRIPTION, MAX, PRIVATE, CREATOR_ID FROM EVENTS WHERE EVENT_ID = {0}".format(event_id))

    event_data = c.fetchall()

    event_name = event_data[0][0]
    event_location = event_data[0][1]
    event_start_time = dateconverter(str(event_data[0][2]))
    event_end_time = dateconverter(str(event_data[0][3]))
    event_details = event_data[0][4]
    max_attendees = event_data[0][5]
    private = event_data[0][6]
    event_creator = event_data[0][7]

    c.execute("SELECT USERS.FIRST_NAME, USERS.LAST_NAME, USERS.EMAIL FROM USERS INNER JOIN EVENTS ON USERS.USER_ID=EVENTS.CREATOR_ID AND EVENTS.EVENT_ID={0}".format(event_id))
    event_coordinator = c.fetchall()
    coordinator_name = event_coordinator[0][0] + ' ' + event_coordinator[0][1]
    coordinator_email = event_coordinator[0][2]
    coordinator_email = coordinator_email.split('@')
    coordinator_id = coordinator_email[0]
    event = [event_id, event_name, event_location, event_start_time, event_end_time, event_details, coordinator_name, coordinator_id, max_attendees, private]
    attendees = get_event_attendees(event_id)
    g.user = current_user.get_id()
    c.execute("SELECT FIRST_NAME, LAST_NAME FROM USERS WHERE EMAIL='{0}'".format(g.user))
    user_attend = c.fetchall()
    name = str(user_attend[0][0] + ' ' + user_attend[0][1])
    user_id = get_sql_id()
    user_check = event_user_check(user_id, event_id)

    if form.submit.data and form.validate_on_submit():
        if user_check == False:
            c.execute("SELECT COUNT(ATTENDEE_ID) FROM EVENT_ATTENDEES WHERE EVENT_ID = {}".format(event_id))
            current = c.fetchall()
            if current[0][0] != None and max_attendees != None:
                if current[0][0] < max_attendees:
                    c.execute("INSERT INTO EVENT_ATTENDEES (EVENT_ID, ATTENDEE_ID) VALUES ({0}, {1})".format(event_id, user_id))
                    app.db.commit()
                    return redirect(url_for('event_page', event_id=event[0], event_full=False))
                else:
                    return redirect(url_for('event_page', event_id=event[0], event_full=True))

    elif leave_button.leave.data and leave_button.validate_on_submit():
        event_leave(event[0])
        return redirect(url_for('event_page', event_id=event[0], event_full=False))


    c.execute("SELECT USER_ID FROM USERS WHERE EMAIL='{0}'".format(g.user))
    owner = c.fetchall()
    delform = DeleteForm()
    
    if event_creator == owner[0][0]:
        if delform.submit2.data and delform.validate():
            c.execute("DELETE FROM COMMENTS WHERE COMMENT_ID = {0}".format(event_id))
            c.execute("DELETE FROM EVENT_ATTENDEES WHERE EVENT_ID = {0}".format(event_id))
            c.execute("DELETE FROM EVENT_TAGS WHERE EVENT_ID = {0}".format(event_id))
            c.execute("DELETE FROM EVENTS WHERE EVENT_ID = {0}".format(event_id))
            flash('Event Successfully Deleted')
            return redirect(url_for('my_events'))


    if form.submit.data and form.validate_on_submit():
        user_id = get_sql_id()
        print(event_id, file=sys.stderr)
        print(user_id, file=sys.stderr)
        c.execute("INSERT INTO EVENT_ATTENDEES (EVENT_ID, ATTENDEE_ID) VALUES ({0}, {1})".format(event_id, user_id))
        app.db.commit()
        return redirect(url_for('event_page', event_id=event[0]))
  
    commentform = CommentForm()
    comment = None

    if commentform.post.data and commentform.validate():
        if name not in attendees:
            return render_template('event.html', data=event, form=form, leave=leave_button, cform=commentform,message="No Comments Have Been Posted", 
                                    message2="Please Join Event to Post Comments", users=attendees,usercheck=user_check)

        else:
            g.user = current_user.get_id()
            c.execute("SELECT FIRST_NAME, LAST_NAME FROM USERS WHERE EMAIL='{0}'".format(g.user)) 
            post_user = c.fetchall() 
            post_comment = commentform.comment.data
            current_time = str(datetime.datetime.now())
            current_time = current_time.split('.')
            c.execute("INSERT INTO COMMENTS(COMMENT_ID, COMMENT, COMMENT_TIME, POST_FNAME, POST_LNAME) VALUES({0},'{1}','{2}','{3}','{4}')".format(
                       event_id, post_comment, current_time[0], post_user[0][0], post_user[0][1]))
            app.db.commit()
            commentform = CommentForm(formdata=None)

    c.execute("SELECT COMMENT, POST_FNAME, POST_LNAME, COMMENT_TIME FROM COMMENTS WHERE COMMENT_ID={0} ORDER BY COMMENT_TIME DESC".format(event_id))
    entries = c.fetchall()

    if not entries:
        return render_template('event.html', data=event, form=form, leave=leave_button, delform=delform, cform=commentform, message="No Comments Have Been Posted", users=attendees,usercheck=user_check, button=button, event_id=event_id)

    else:
        return render_template('event.html', data=event, form=form, leave=leave_button, delform=delform, cform=commentform, entries=entries, users=attendees,usercheck=user_check, button=button,event_id=event_id)
    
    return render_template('event.html', data=event, form=form, leave=leave_button, cform=commentform, entries=entries, users=attendees, eventid=event_id, usercheck=user_check,button=button)

#SHOWS EVENTS THE LOGGED IN USER HAS CREATED
@app.route('/myevents/')
@login_required
def my_events():

    if not app.db:
            connect_db()

    c = app.db.cursor()
    g.user = current_user.get_id()
    c.execute("SELECT USER_ID from USERS WHERE EMAIL='{0}'".format(g.user))
    user_info = c.fetchall()
    user_id = user_info[0][0]

    g.user = current_user.get_id()

    events = []

    c.execute("SELECT EVENT_NAME, LOCATION, START_TIME, END_TIME, DESCRIPTION, EVENT_ID FROM EVENTS WHERE CREATOR_ID={0}".format(user_id))
    events_info = c.fetchall()

    for event in events_info:
        event_name = event[0]
        event_location = event[1]
        event_start_time = event[2]
        event_end_time = event[3]
        event_description = event[4]
        event_id = event[5]

        events.append([event_name, event_location, event_start_time, event_end_time, event_description, event_id])


    return render_template('myevents.html', data=events)

#SHOWS GROUPS THE LOGGED IN USER HAS CREATED
@app.route('/mygroups')
@login_required
def my_groups():
    if not app.db:
        connect_db()

    c = app.db.cursor()
    g.user = current_user.get_id()
    c.execute("SELECT USER_ID from USERS WHERE EMAIL='{0}'".format(g.user))
    user_info = c.fetchall()
    user_id = user_info[0][0]

    g.user = current_user.get_id()
    
    groups = []

    c.execute("SELECT GROUP_NAME, GROUP_DESCRIPTION, GROUP_ID FROM GROUPS WHERE GROUP_OWNER_ID={0}".format(user_id))
    groups_info = c.fetchall()

    for group in groups_info:
        group_name = group[0]
        group_description = group[1]
        group_id = group[2]

        groups.append([group_name, group_description, group_id])

    return render_template('mygroups.html', data=groups)

#View all events in database
@app.route('/viewevents')
@login_required
def view_events():

        if not app.db:
                connect_db()

        c = app.db.cursor()
        c.execute("SELECT * FROM EVENTS WHERE START_TIME >= NOW()")
        events_info = c.fetchall()    
        events = []

        for event in events_info:
                event_id = event[0]
                event_name = event[1]
                event_location = event[2]
                event_start_time = dateconverter(str(event[3]))
                event_end_time = dateconverter(str(event[4]))
                event_description = event[6]
                events.append([event_id, event_name, event_location, event_start_time, event_end_time, event_description])

        return render_template('viewevents.html', data=events)
 
#Queries db and returns list of new groups
def newest_groups():
        if not app.db:
                connect_db()

        c = app.db.cursor()
        c.execute('SELECT GROUP_ID, GROUP_NAME, GROUP_DESCRIPTION FROM GROUPS ORDER BY GROUP_ID DESC LIMIT 10;')
        newest_groups = c.fetchall()
    
        groups = []
        for group in newest_groups:
                if len(groups) < 3:
                        group_id = group[0]
                        group_name = group[1]
                        group_description = group[2]
       
                        groups.append([group_id, group_name, group_description])

                else:
                        pass

        return groups


#Queries db and returns list of new users
def newest_users():
        if not app.db:
                connect_db()

        c = app.db.cursor()
        c.execute('SELECT USER_ID, FIRST_NAME, LAST_NAME, MAJOR, AVATAR, EMAIL FROM USERS ORDER BY USER_ID DESC LIMIT 10;')
        newest_users = c.fetchall()
    
        users = []
        for user in newest_users:
                if len(users) < 3:
                        user_id = user[0]
                        user_fname = user[1]
                        user_lname = user[2]
                        user_major = user[3]
                        user_avatar = user[4]
                        user_email = user[5]
                        user_email = user_email.split('@')[0]
       
                        users.append([user_id, user_fname, user_lname, user_major, user_avatar, user_email])

                else:
                        pass

        return users
      
# logging out is managed by login manager
# Log out option appears on the navbar only after a user logs on
# successfully (see lines 25-29 of templates/base.html )
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/interest_groups/', methods=['GET', 'POST'])
@login_required
def add_details():
        success = False
        if not app.db:
                connect_db()
        g.user = current_user.get_id()
        group_name = None
        group_description = None
        group_secondary_tags = []
        primary_tags_list = get_values('SELECT TAG_ID, TAG_TITLE FROM TAGS \
                WHERE isPRIMARY=1 ORDER BY TAG_TITLE;')
        primary_tags = []
        for tag in primary_tags_list:
                primary_tags.append((str(tag[0]),tag[1]))
        form = interest_group_form(primary_tags)
        if form.validate_on_submit():
                success = True
                group_name = form.group_name.data
                group_description = form.group_description.data
                group_primary_tag = form.group_primary_tag.data
                group_secondary_tags = form.group_secondary_tags.data
                group_secondary_tags = separate_tags(group_secondary_tags)
                private = form.private.data
                if private:
                        private = 1
                else:
                        private = 0
                user_info = get_values("SELECT USER_ID from USERS WHERE EMAIL='{0}'".format(g.user))
                user_ID = user_info[0][0]
                change_values('INSERT INTO  GROUPS(GROUP_NAME, GROUP_DESCRIPTION, GROUP_OWNER_ID, PRIVATE_GROUP) \
                        VALUES("{}", "{}", {}, {});'.format(group_name, group_description, user_ID, private))
                group_ID = get_values('SELECT GROUP_ID from GROUPS where GROUP_NAME="{}";'.format(group_name))
                group_ID = group_ID[0][0]
                change_values('INSERT INTO GROUP_TAGS VALUES({},{})'.format(group_ID, group_primary_tag))
                change_values('INSERT INTO GROUP_MEMBERS VALUES({},{});'.format(group_ID, user_ID))
                if group_secondary_tags:
                        for secondary_tag in group_secondary_tags:
                                if not get_values('SELECT TAG_TITLE FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag)):
                                        change_values('INSERT INTO TAGS(TAG_TITLE, isPRIMARY) VALUES("{}", 0);'.format(secondary_tag))
                                        secondary_tag_ID = get_values('SELECT TAG_ID FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag))
                                        change_values('INSERT INTO GROUP_TAGS VALUES({}, {});'.format(group_ID, secondary_tag_ID[0][0]))
                form.group_name.data = ''
                form.group_description.data = ''
                form.group_primary_tag = ''
                form.group_secondary_tags = ''
                form.private = ''
                return redirect(url_for('view_group', group_ID=group_ID))
        return render_template('interest_groups.html', form=form, name=group_name, \
                desc=group_description, success=success)

#VIEWS THE GROUP ASSOCIATED BY ITS ID
@app.route('/view_group/<group_ID>', methods=['GET', 'POST'])
def view_group(group_ID):
        if not app.db:
                connect_db()
        c = app.db.cursor()

        form = GroupPage()
        leave_button = LeaveButton()

        button=False
        if is_group_owner(group_ID):
            button=True

        g.user = current_user.get_id()
        user_ID = get_values('SELECT USER_ID FROM USERS WHERE EMAIL="{}"'.format(g.user))
        group = get_values('SELECT GROUP_NAME, GROUP_OWNER_ID, GROUP_DESCRIPTION, PRIVATE_GROUP \
                FROM GROUPS WHERE GROUP_ID={};'.format(group_ID))
        name = group[0][0].strip("'")
        creator_ID = group[0][1]
        creator = get_values('SELECT FIRST_NAME, LAST_NAME FROM USERS WHERE USER_ID="{}";'.format(creator_ID))
        creator = creator[0][0] + " " + creator [0][1]
        description = group[0][2].strip("'")
        private = group[0][3]

        members = get_group_members(group_ID)
        ##Gets the EMAIL of group owner to link to his/her profile page
        c.execute("SELECT EMAIL FROM USERS WHERE USER_ID='{0}'".format(creator_ID))
        creator_email_info = c.fetchall()
        creator_email = creator_email_info[0][0]
        creator_email_split = creator_email.split('@')
        email = creator_email_split[0]

        delform = DeleteForm()
        user_check = group_user_check(user_ID[0][0], group_ID)

        if form.submit.data:
            if user_check == False:
                c.execute("INSERT INTO GROUP_MEMBERS (GROUP_ID, MEMBER_ID) VALUES ({0}, {1})".format(group_ID, user_ID[0][0]))
                app.db.commit()
                return redirect(url_for('view_group', group_ID=group_ID))
            else:
                return redirect(url_for('view_group', group_ID=group_ID))

        elif leave_button.leave.data and leave_button.validate_on_submit():
            group_leave(group_ID, user_ID[0][0])
            return redirect(url_for('view_group', group_ID=group_ID))


        if creator_ID == user_ID[0][0]:
            if delform.submit2.data and delform.validate():
                c.execute("DELETE FROM COMMENTS_GROUPS WHERE COMMENT_ID = {0}".format(group_ID))
                c.execute("DELETE FROM GROUP_TAGS WHERE GROUP_ID = {0}".format(group_ID))
                c.execute("DELETE FROM GROUP_MEMBERS WHERE GROUP_ID = {0}".format(group_ID))
                c.execute("DELETE FROM GROUPS WHERE GROUP_ID = {0}".format(group_ID))
                flash('Group Successfully Deleted')
                return redirect(url_for('my_groups'))

        group_info = [name, creator, creator_ID, email, description, private, group_ID]


        c.execute("SELECT FIRST_NAME, LAST_NAME FROM USERS WHERE EMAIL='{0}'".format(g.user))
        user_attend = c.fetchall()
        name = str(user_attend[0][0] + ' ' + user_attend[0][1])

        commentform = CommentForm()
        comment = None

        if commentform.post.data and commentform.validate():
            if name not in members:
                return render_template('view_group.html', data=group_info, cform=commentform, message="No Comments Have Been Posted", 
                                        message2="Please Join Group to Post Comments", users=members, form=form, leave=leave_button, usercheck=user_check)

            else:
                g.user = current_user.get_id()
                c.execute("SELECT FIRST_NAME, LAST_NAME FROM USERS WHERE EMAIL='{0}'".format(g.user)) 
                post_user = c.fetchall() 
                post_comment = commentform.comment.data
                current_time = str(datetime.datetime.now())
                current_time = current_time.split('.')
                c.execute("INSERT INTO COMMENTS_GROUPS(COMMENT_ID, COMMENT, COMMENT_TIME, POST_FNAME, POST_LNAME) VALUES({0},'{1}','{2}','{3}','{4}')".format(
                           group_ID, post_comment, current_time[0], post_user[0][0], post_user[0][1]))
                app.db.commit()
                commentform = CommentForm(formdata=None)

        c.execute("SELECT COMMENT, POST_FNAME, POST_LNAME, COMMENT_TIME FROM COMMENTS_GROUPS WHERE COMMENT_ID={0} ORDER BY COMMENT_TIME DESC".format(group_ID))
        entries = c.fetchall()

        if not entries:
            return render_template('view_group.html', data=group_info,delform=delform,cform=commentform, message="No Comments Have Been Posted", users=members, group_id=group_ID, button=button, form=form, leave=leave_button, usercheck=user_check)

        else:
            return render_template('view_group.html', data=group_info,delform=delform, cform=commentform, entries=entries, users=members, group_id=group_ID, button=button, form=form, leave=leave_button, usercheck=user_check)
        
        return render_template('view_group.html', data=group_info, delform=delform, cform=commentform, users=members, group_id=group_ID, button=button, form=form, leave=leave_button, usercheck=user_check)

#DISPLAY EVENT OF GROUP
@app.route('/group_events/<group_ID>', methods=['GET', 'POST'])
def group_events(group_ID):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    c.execute("SELECT * FROM EVENTS WHERE GROUP_ID={0}".format(group_ID))
    events_info = c.fetchall()    
    events = []

    for event in events_info:
        event_id = event[0]
        event_name = event[1]
        event_location = event[2]
        event_start_time = dateconverter(str(event[3]))
        event_end_time = dateconverter(str(event[4]))
        event_description = event[6]
        events.append([event_id, event_name, event_location, event_start_time, event_end_time, event_description, group_ID])

    return render_template('group_events.html', data=events, group_ID=group_ID)


#Views Groups
@app.route('/view_groups', methods=['GET'])
def view_all_groups():
        if not app.db:
                connect_db()
        groups_list = get_values('SELECT GROUP_NAME, GROUP_OWNER_ID, GROUP_DESCRIPTION, \
                GROUP_ID FROM GROUPS;')
        groups = []
        group_IDs = []
        for i in range(len(groups_list)):
                group = []
                group.append(groups_list[i][0])
                creator = get_values('SELECT FIRST_NAME, \
                        LAST_NAME FROM USERS WHERE USER_ID="{}";'.format(groups_list[i][1]))
                group.append(creator[0][0] + " " + creator[0][1]) 
                group.append(groups_list[i][2])
                group.append(groups_list[i][3])
                groups.append(group)

        return render_template('view_groups.html', groups=groups)


#Searches function for users, groups, and events all at once
@app.route('/results/', methods=['GET', 'POST'])
def search_result(search):
        connect_db()
        c = app.db.cursor()

        g.user = current_user.get_id()
        user_results=[]
        event_results=[]
        group_results=[]
   
  
        searches = search.data['search']
        formatted_query = "%" + searches + "%"

        #User search
        query = 'SELECT USER_ID, FIRST_NAME, LAST_NAME FROM USERS\
                WHERE FIRST_NAME LIKE "{}" OR LAST_NAME LIKE "{}";'\
                .format(formatted_query, formatted_query)
        results_list = get_values(query)
        user_results = results_list #FIXME


        #Event search
        query = 'SELECT DISTINCT EVENTS.EVENT_ID, EVENTS.EVENT_NAME, LOCATION, START_TIME, DESCRIPTION FROM TAGS\
                INNER JOIN EVENT_TAGS ON TAGS.TAG_ID=EVENT_TAGS.TAG_ID\
                INNER JOIN EVENTS ON EVENT_TAGS.EVENT_ID=EVENTS.EVENT_ID\
                WHERE TAGS.TAG_TITLE LIKE "{}" AND TAGS.isPRIMARY=0\
                OR EVENTS.EVENT_NAME LIKE "{}";'.format(formatted_query, formatted_query)
        results_list = get_values(query)
        event_results = results_list #FIXME 


        #Group search
        query =  'SELECT DISTINCT GROUPS.GROUP_ID, GROUPS.GROUP_NAME, GROUPS.GROUP_DESCRIPTION FROM TAGS\
                INNER JOIN GROUP_TAGS ON TAGS.TAG_ID=GROUP_TAGS.TAG_ID\
                INNER JOIN GROUPS ON GROUP_TAGS.GROUP_ID=GROUPS.GROUP_ID\
                WHERE TAGS.TAG_TITLE LIKE "{}" AND TAGS.isPRIMARY=0\
                OR GROUPS.GROUP_NAME LIKE "{}";'.format(formatted_query, formatted_query)
        results_list = get_values(query)
        group_results = results_list

        return render_template('search.html', user_results=user_results,\
                event_results=event_results, group_results=group_results)

#FUNCTION TO EDIT EVENT INFORMATION
@app.route('/edit_event/<event_ID>', methods=['GET', 'POST'])
@login_required
def edit_event(event_ID):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    primary_tags = get_primary_tags()
    form = event_add(primary_tags)
    name = None
    location = None
    starttime = None
    endtime = None
    primary_tag = None
    secondary_tags = None
    description = None
    max_attendees = None
    private = False

    infos = []


    c.execute("SELECT * FROM EVENTS WHERE EVENT_ID = {0}".format(event_ID))
    info = c.fetchall()

    c.execute("SELECT TAGS.TAG_TITLE FROM EVENTS INNER JOIN EVENT_TAGS ON EVENTS.EVENT_ID=EVENT_TAGS.EVENT_ID INNER JOIN TAGS ON EVENT_TAGS.TAG_ID=TAGS.TAG_ID WHERE TAGS.isPRIMARY=0 and EVENTS.EVENT_ID={0}".format(event_ID))
    secondary_tags = c.fetchall()

    c.execute("SELECT TAGS.TAG_TITLE FROM EVENTS INNER JOIN EVENT_TAGS ON EVENTS.EVENT_ID=EVENT_TAGS.EVENT_ID INNER JOIN TAGS ON EVENT_TAGS.TAG_ID=TAGS.TAG_ID WHERE TAGS.isPRIMARY=1 and EVENTS.EVENT_ID={0}".format(event_ID))
    primary_tag = c.fetchall()

    sec_tags = ""
    for tags in secondary_tags:
        for t in tags:
            sec_tags += t + ','
    
    for i in info:
        e_name = i[1]
        e_loc = i[2]
        e_start = i[3]
        e_end = i[4]
        e_desc = i[6]
        e_max = i[7]
        e_private = i[8]

        infos.append([e_name, e_loc, e_start, e_end, primary_tag[0][0], sec_tags, e_desc, e_max, e_private])

    if form.validate_on_submit():
        name = form.name.data
        location = form.location.data
        starttime = form.starttime.data
        endtime = form.endtime.data
        primary = form.primary_tag.data
        secondaries = form.secondary_tags.data
        secondaries = separate_tags(secondaries)
        description = form.description.data
        max_attendees = form.max_attendees.data
        private = form.is_private.data
        print("VALIDATED ON SUBMIT!", file=sys.stderr)

        #SOMETHING IS WRONG WITH THIS QUERY I THINK
        c.execute("UPDATE EVENTS SET EVENT_NAME = '{0}', LOCATION = '{1}', START_TIME = '{2}', END_TIME = '{3}', DESCRIPTION = '{4}', MAX = {6}, PRIVATE = {7} WHERE EVENT_ID = '{5}'".format(name, location, starttime, endtime, description, event_ID, max_attendees, private))
        c.execute("DELETE FROM EVENT_TAGS WHERE EVENT_ID={0}".format(event_ID))
        change_values('INSERT INTO EVENT_TAGS VALUES({},{})'.format(event_ID, primary))
        if secondaries:
                for secondary_tag in secondaries:
                        if not get_values('SELECT TAG_TITLE FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag)):
                                change_values('INSERT INTO TAGS(TAG_TITLE, isPRIMARY) VALUES("{}", 0);'.format(secondary_tag))
                                secondary_tag_ID = get_values('SELECT TAG_ID FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag))
                                change_values('INSERT INTO EVENT_TAGS VALUES({}, {});'.format(event_ID, secondary_tag_ID[0][0]))
        app.db.commit()
        return redirect(url_for('event_page', event_id=event_ID))

    return render_template('editevent.html', form=form, infos=infos)

#FUNCTION TO EDIT GROUP INFORMATION.
@app.route('/edit_group/<group_id>', methods=['GET', 'POST'])
@login_required
def edit_group(group_id):
    if not app.db:
        connect_db()

    c = app.db.cursor()
    primary_tag = get_primary_tags()
    form = interest_group_form(primary_tag)
    name=None
    description=None
    prim_tag=None
    secondary_tagss=None
    private = False

    infos = []
    

    c.execute("SELECT * FROM GROUPS WHERE GROUP_ID = {0}".format(group_id))
    info = c.fetchall()
    
    c.execute("SELECT TAGS.TAG_TITLE FROM GROUPS INNER JOIN GROUP_TAGS ON GROUPS.GROUP_ID=GROUP_TAGS.GROUP_ID INNER JOIN TAGS ON GROUP_TAGS.TAG_ID=TAGS.TAG_ID WHERE TAGS.isPRIMARY=0 and GROUPS.GROUP_ID={0}".format(group_id))
    secondary_tags = c.fetchall()

    c.execute("SELECT TAGS.TAG_TITLE FROM GROUPS INNER JOIN GROUP_TAGS ON GROUPS.GROUP_ID=GROUP_TAGS.GROUP_ID INNER JOIN TAGS ON GROUP_TAGS.TAG_ID=TAGS.TAG_ID WHERE TAGS.isPRIMARY=1 and GROUPS.GROUP_ID={0}".format(group_id))
    prim_tag = c.fetchall()

    sec_tags = ""
    for tags in secondary_tags:
        for t in tags:
            sec_tags += t + ','
    
    for i in info:
        e_name = i[1]
        e_desc = i[3]

        infos.append([e_name, e_desc, prim_tag[0][0], sec_tags])


    if form.validate_on_submit():
        name = form.group_name.data
        description = form.group_description.data
        primary = form.group_primary_tag.data
        secondaries = form.group_secondary_tags.data
        secondaries = separate_tags(secondaries)
        private = form.private.data
        print(name, file=sys.stderr)
        c.execute("UPDATE GROUPS SET GROUP_NAME = '{0}', GROUP_DESCRIPTION = " + "{1}" + ", PRIVATE_GROUP={2} WHERE GROUP_ID = '{3}'".format(name, description, private, group_id))
        c.execute("DELETE FROM GROUP_TAGS WHERE GROUP_ID={0}".format(group_id))
        change_values('INSERT INTO GROUP_TAGS VALUES({},{})'.format(group_id, primary))
        if secondaries:
                for secondary_tag in secondaries:
                        if not get_values('SELECT TAG_TITLE FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag)):
                                change_values('INSERT INTO TAGS(TAG_TITLE, isPRIMARY) VALUES("{}", 0);'.format(secondary_tag))
                                secondary_tag_ID = get_values('SELECT TAG_ID FROM TAGS WHERE TAG_TITLE="{}";'.format(secondary_tag))
                                change_values('INSERT INTO GROUP_TAGS VALUES({}, {});'.format(group_id, secondary_tag_ID[0][0]))
        app.db.commit()
        return redirect(url_for('view_group', group_ID=group_id))

    return render_template('editgroup.html', form=form, infos=infos)

    
#DELETE GROUP
@app.route('/delete_group/<groupid>/')
def delete_group(groupid):
    if not app.db:
        connect_db()

    c = app.db.cursor()
    c.execute("DELETE FROM COMMENTS_GROUPS WHERE COMMENT_ID = {0}".format(groupid))
    c.execute("DELETE FROM GROUP_TAGS WHERE GROUP_ID = {0}".format(groupid))
    c.execute("DELETE FROM GROUP_MEMBERS WHERE GROUP_ID = {0}".format(groupid))
    c.execute("DELETE FROM GROUPS WHERE GROUP_ID = {0}".format(groupid))
    app.db.commit()

    return redirect(url_for('my_groups'))

#Delete Events
@app.route('/delete_event/<eventid>/')
def delete_event(eventid):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    c.execute("DELETE FROM COMMENTS WHERE COMMENT_ID = {0}".format(eventid))
    c.execute("DELETE FROM EVENT_ATTENDEES WHERE EVENT_ID = {0}".format(eventid))
    c.execute("DELETE FROM EVENT_TAGS WHERE EVENT_ID = {0}".format(eventid))
    c.execute("DELETE FROM EVENTS WHERE EVENT_ID = {0}".format(eventid))

    app.db.commit()

    return redirect(url_for('my_events'))

######
#HELPER FUNCTIONS#
######
#Executes SQL query based on input, does not return any values
def change_values(query):
        c = app.db.cursor()
        c.execute(query)
        app.db.commit()

def get_values(query):
    c = app.db.cursor()
    c.execute(query)
    new_list = c.fetchall()
    return new_list


#Returns list of tags
def separate_tags(tags):
        tag_list = tags.split(',')
        for i in range(len(tag_list)):
                tag_list[i] = tag_list[i].strip()
        return tag_list

def format_string(string):
    new_string = ''
    for char in range(len(string)):
        if string[char].isalnum() or string[char] == ',' or string[char] or string[char].isspace():
            new_string += string[char]
    return ';'.join(new_string.split(','))

#Returns USER_ID of current logged in user
def get_sql_id():
    if not app.db:
        connect_db()

    c = app.db.cursor()
    g.user = current_user.get_id()

    c.execute("SELECT USER_ID FROM USERS WHERE EMAIL='{0}'".format(g.user))
    result = c.fetchall()

    return result[0][0]

#Returns first and last name of user based on their ID
def get_name_by_id(user_id):
    if not app.db:
        connect_db()

    c = app.db.cursor()
    c.execute("SELECT FIRST_NAME, LAST_NAME FROM USERS WHERE USER_ID = {0}".format(user_id))
    user_results = c.fetchall()
    name_string = ''

    for index in user_results:
        name_string += index[0] + ' ' + index[1]

    return name_string

#Gets list of all active users in event
def get_event_attendees(event_id):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    c.execute("SELECT ATTENDEE_ID FROM EVENT_ATTENDEES WHERE EVENT_ID = {0}".format(event_id))
    attendees = c.fetchall()

    attendees_list = []

    for attendee in attendees:
        person = get_name_by_id(attendee[0])
        attendees_list.append(person)

    return attendees_list

#Returns list of all primary tags
def get_primary_tags():
        primary_tags_list = get_values('SELECT TAG_ID, TAG_TITLE FROM TAGS \
                WHERE isPRIMARY=1 ORDER BY TAG_TITLE;')
        primary_tags = []
        for tag in primary_tags_list:
                primary_tags.append((str(tag[0]),tag[1]))
        return primary_tags

#Gets list of all active users in event
def get_group_members(group_id):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    c.execute("SELECT MEMBER_ID FROM GROUP_MEMBERS WHERE GROUP_ID = {0}".format(group_id))
    members = c.fetchall()

    members_list = []

    for member in members:
        person = get_name_by_id(member[0])
        members_list.append(person)

    return members_list

#Converts Date to proper SQL format
def dateconverter(d):
    months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 
    'August', 'September', 'October', 'November', 'December']
    date_string_split = d.split('-')
    second_date_string_split = date_string_split[2].split(' ')

    new_s = months[int(date_string_split[1]) - 1] + ' ' + second_date_string_split[0] + ' ' + date_string_split[0] + ' ' + second_date_string_split[1]


    return new_s

#CHECKS IF USER OWNS GROUPS
def is_group_owner(group_id):
    if not app.db:
        connect_db()

    email = current_user.get_id()
    c = app.db.cursor()
    c.execute("SELECT USER_ID FROM USERS WHERE EMAIL='{0}'".format(email))
    user = c.fetchall()

    c.execute("SELECT GROUP_OWNER_ID FROM GROUPS WHERE GROUP_ID='{0}'".format(group_id))
    owner = c.fetchall()

    if user[0][0] == owner[0][0]:
        return True
    else:
        return False

#CHECK IF USER OWNS EVENTS
def is_event_owner(event_id):

    if not app.db:
       connect_db()

    email = current_user.get_id()
    c = app.db.cursor()
    c.execute("SELECT USER_ID FROM USERS WHERE EMAIL='{0}'".format(email))
    user = c.fetchall()

    c.execute("SELECT CREATOR_ID FROM EVENTS WHERE EVENT_ID='{0}'".format(event_id))
    owner = c.fetchall()


    if user[0][0] == owner[0][0]:
        return True
    else:
        return False 

#LEAVES AN EVENT
def event_leave(event_id):
    if not app.db:
        connect_db()

    g.user = current_user.get_id()

    #GET USER ID
    c = app.db.cursor()
    c.execute("SELECT USER_ID FROM USERS WHERE EMAIL = '{0}'".format(g.user))
    user_info = c.fetchall()
    user_id = user_info[0][0]

    c.execute("DELETE FROM EVENT_ATTENDEES WHERE EVENT_ID = '{0}' AND ATTENDEE_ID = '{1}'".format(event_id, user_id))

    return 'Left Event'

#LEAVE GROUP
def group_leave(group_id, user_id):
    if not app.db:
        connect_db()

    g.user = current_user.get_id()
    c = app.db.cursor()
    
    c.execute("DELETE FROM GROUP_MEMBERS WHERE GROUP_ID = '{0}' AND MEMBER_ID = '{1}'".format(group_id, user_id))

    return 'Left Group'

#Checks to see if user is in event
def event_user_check(user_id, event_id):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    c.execute("SELECT ATTENDEE_ID FROM EVENT_ATTENDEES WHERE ATTENDEE_ID = '{0}' AND EVENT_ID = '{1}'".format(user_id, event_id))
    result = c.fetchall()

    #If the field is populated, means user is in the event.
    if result != ():
        return True

    return False


#Check if user is in group
def group_user_check(user_id, group_id):
    if not app.db:
        connect_db()

    c = app.db.cursor()

    c.execute("SELECT MEMBER_ID FROM GROUP_MEMBERS WHERE MEMBER_ID = {0} AND GROUP_ID = {1}".format(user_id, group_id))
    result = c.fetchall()

    #If the field is populated, means user is in the group.
    if result != ():
        return True

    return False

def my_events_home():
    if not app.db:
        connect_db()

    c = app.db.cursor()

    g.user = current_user.get_id()

    #GET USER_ID
    c.execute("SELECT USER_ID FROM USERS WHERE EMAIL = '{0}'".format(g.user))
    user_id = c.fetchall()
    counter = 0
    index = 0

    c.execute("SELECT EVENT_ID FROM EVENT_ATTENDEES WHERE ATTENDEE_ID = {0}".format(user_id[0][0]))
    event_ids = c.fetchall()

    #GET EVENTS ASSOCIATED WITH USER ID
    c.execute("SELECT EVENT_ID, EVENT_NAME, LOCATION, START_TIME, DESCRIPTION FROM EVENTS WHERE CREATOR_ID={0}".format(user_id[0][0]))   
    event_tuple = c.fetchall()
    event_info = []

    #GET EVENT DESCRIPTION USER IS ASSOCIATED WITH
    for eventid in event_ids:
        c.execute("SELECT EVENT_NAME, LOCATION, START_TIME, DESCRIPTION FROM EVENTS WHERE EVENT_ID={0}".format(eventid[0]))
        query_info = c.fetchall()
        l = [eventid[0]]
        if counter < 3:
            for entry in query_info:
                for info in entry:
                    if index != 2:
                        pass

                    else:
                        info = info.strftime('%m/%d/%Y')
                    
                    l.append(info)
                    index += 1
        else:
            break

        event_info.append(l)
        counter += 1
        index = 0

    return event_info

#DISPLAYS UPCOMING EVENTS
def upcoming_events():
    if not app.db:
        connect_db()

    now = str(datetime.datetime.now())
    now = now.split('.')
    c = app.db.cursor()
    c.execute('SELECT EVENT_ID, LOCATION, EVENT_NAME, START_TIME, DESCRIPTION FROM EVENTS WHERE START_TIME >= NOW() ORDER BY START_TIME ASC LIMIT 10'.format(now[0]))
    upcoming_events = c.fetchall()

    events = []
    for event in upcoming_events:
        if len(events) < 3:
            event_id = event[0]
            event_location = event[1]
            event_name = event[2]
            event_start_time = event[3].strftime('%m/%d/%Y')
            event_description = event[4]

            events.append([event_id, event_name, event_location, event_start_time, event_description])

        else:
            pass


    return events

#GET PAST USER EVENTS  
def get_past_user_event(user_id):
	if not app.db:
		connect_db()

	c = app.db.cursor()

	c.execute("SELECT EVENT_NAME, LOCATION, START_TIME, DESCRIPTION FROM EVENTS EVENT_ATTENDEES WHERE ATTENDEE_ID = '{0}' AND EVENT_ATTENDEES.EVENT_ID = EVENTS.EVENT_ID AND START_TIME < NOW()".format(user_id))
	result =c.fetchall()

	return result

def get_group_event(group_id):
	if not app.db:
		connect_db()

	c = app.db.cursor

	c.execute("SELECT EVENT_NAME, LOCATION, START_TIME, END_TIME, DESCRIPTION FROM EVENTS WHERE EVENTS.GROUP_ID = '{0}'".format(group_id))

	result = c.fetchall

	return result


