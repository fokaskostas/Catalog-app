#!/usr/bin/env python3

from flask import Flask, render_template, request, redirect, jsonify, url_for,  flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON endpoint for categories
@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[r.serialize for r in categories])


# JSON endpoint for items in category
@app.route('/<category_name>/items/JSON')
def showItemsJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(category=category).all()
    return jsonify(items=[r.serialize for r in items])


# JSON endpoint for item
@app.route('/<category_name>/items/<item_name>/JSON')
def ItemJSON(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).first()
    item = session.query(Item).filter_by(name=item_name).first()
    return jsonify(item=[item.serialize])


# Welcome page
@app.route('/')
def welcome():
    return render_template('welcome.html')


# Show all categories
@app.route('/home')
def showCategories():
    categories = session.query(Category).all()
    return render_template('home.html', categories=categories)


# Add a new Category
@app.route('/category/new', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        flash('You must be logged in!')
        return redirect('/login')
    if request.method == 'POST':
        addedCategory = Category(name=request.form['name'])
        session.add(addedCategory)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


# Edit a Category
@app.route('/<path:category_name>/edit', methods=['GET', 'POST'])
def editCategory(category_name):
    if 'username' not in login_session:
        flash('You must be logged in!')
        return redirect('/login')
    editedCategory = session.query(Category).filter_by(name=category_name).one()
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            session.add(editedCategory)
            session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=editedCategory)


# Delete a Category
@app.route('/<path:category_name>/delete', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'username' not in login_session:
        flash('You must be logged in!')
        return redirect('/login')
    deletedCategory = session.query(Category).filter_by(name=category_name).first()
    if request.method == 'POST':
        session.delete(deletedCategory)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('deletecategory.html', category=deletedCategory)


# Show a category's items
@app.route('/<path:category_name>')
@app.route('/<path:category_name>/items')
def showItems(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(category=category).all()
    return render_template('items.html', category=category, items=items)


# Show an item's description
@app.route('/<path:category_name>/items/<path:item_name>')
def showItemDescription(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).first()
    return render_template('itemDescription.html', item=item)


# Add a new Item
@app.route('/<path:category_name>/items/new', methods=['GET', 'POST'])
def newItem(category_name):
    if 'username' not in login_session:
        flash('You must be logged in!')
        return redirect('/login')
    if request.method == 'POST':
        addedItem = Item(name=request.form['name'], description=request.form['description'], category=session.query(Category).filter_by(name=request.form['category']).one())
        session.add(addedItem)
        session.commit()
        return redirect(url_for('showItems', category_name=category_name))
    else:
        return render_template('newItem.html', category_name=category_name)


# Edit Item
@app.route('/<path:category_name>/<path:item_name>/edit', methods=['GET', 'POST'])
def editItem(category_name, item_name):
    if 'username' not in login_session:
        flash('You must be logged in!')
        return redirect('/login')
    editedItem = session.query(Item).filter_by(name=item_name).first()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.category = session.query(Category).filter_by(name=request.form['category']).one()
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showItems', category_name=category_name))
    else:
        return render_template('editItem.html', category_name=category_name, item_name=item_name)


# Delete Item
@app.route('/<path:category_name>/<path:item_name>/delete', methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    if 'username' not in login_session:
        flash('You must be logged in!')
        return redirect('/login')
    deletedItem = session.query(Item).filter_by(name=item_name).first()
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        return redirect(url_for('showItems', category_name=category_name))
    else:
        return render_template('deleteItem.html', category_name=category_name, item_name=item_name)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
