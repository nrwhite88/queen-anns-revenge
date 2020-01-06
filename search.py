from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, RadioField
from wtforms.validators import DataRequired

import getpass, pymysql, sys

import difflib
from difflib import get_close_matches

app = Flask(__name__)
app.db = None
app.config['SECRET_KEY'] = 'hard to guess string'

bootstrap = Bootstrap(app)
moment = Moment(app)


class SearchForm(FlaskForm):
	search_query = StringField('Enter search:', validators=[DataRequired()])
	search_type = RadioField('Display results for:', choices=[('users', 'Users'),\
		('events','Events'),('groups','Groups')],default='users')
	submit = SubmitField('Submit')


@app.route('/search/', methods=['GET', 'POST'])
def search():
	success = False
	check_connection()
	search_query = None
	search_type = None
	form = SearchForm()
	results = []
	if form.validate_on_submit():
		success = True
		search_query = form.search_query.data
		search_type = form.search_type.data
		form.search_query.data = ''
		form.search_type.data = ''
		if search_type == 'users':
			query = 'SELECT * FROM Users WHERE FIRST_NAME="{}";'.format(search_query)
			results_list = db_query(query)
			for i in range(len(results_list)):
				results.append(format_string(str(results_list[i])))
				results[i] = results[i].split(';')
			#results = format_string(results)
			print("Results:", results)
		elif search_type == 'events':
			temp = db_query(search_query)
			results = format_string(temp)
		elif search_type == 'groups':
			temp = db_query(search_query)
			results = format_string(temp)
		return render_template('search.html', form=form, results=results)
	return render_template('search.html', form=form, results=results)


#Connects to database
def connect_db():
        if not app.db:
                db_IP = input('Input DB server IP address: ')
                pswd = getpass.getpass('Password: ')
                app.db = pymysql.connect(db_IP, 'root', pswd, 'SCSU')
        else:
                print('Connected!', file=sys.stderr)

#Checks connection to database, connects if there is no connection
def check_connection():
	if not app.db:
		connect_db()


#Executes SQL query based on input, does not return any values
def db_query(query):
	c = app.db.cursor()
	print(query, file=sys.stderr)
	c.execute(query)
	new_list = c.fetchall()

	print(new_list, file=sys.stderr)

	return new_list

#Removes unnecessary characters and returns a formatted string with separations via semicolon
def format_string(string):
	new_string = ''
	for char in range(len(string)):
		if string[char].isalnum() or string[char] == ',' or string[char].isspace():
			new_string += string[char]
	return ' '.join(new_string.split(','))


def match_words(userword):
	if userword in data:
		print("Found!")
	else:
		closest = get_close_matches(userword, data)
	if closest:
		print("Found", closest)
		return closest
	else:
		print("No results.")
		return 'No results.'
