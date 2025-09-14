import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, url_for, flash, redirect, session,request
from flask_redis import FlaskRedis
from forms import RegistrationForm, LoginForm, AddAccountForm
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_socketio import SocketIO, emit # Import SocketIO
from telethon.sync import TelegramClient
from telethon.errors import SessionPasswordNeededError
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError
from flask_pymongo import PyMongo # Import PyMongo
from dotenv import load_dotenv # Import the function
import asyncio


load_dotenv()

# --- App Initialization ---
app = Flask(__name__)
socketio = SocketIO(app) 

# --- Configuration ---
app.config['SECRET_KEY'] = os.urandom(24) 

# ** MODIFIED LINE: Use your Redis Cloud connection string **
app.config['REDIS_URL'] =os.environ.get("REDIS_URL")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
# --- Extensions Initialization ---
redis_client = FlaskRedis(app, decode_responses=True) # Added decode_responses=True
mongo = PyMongo(app)
socketio = SocketIO(app, message_queue=app.config['REDIS_URL'])

# Configure Flask-PyMongo
# Assumes MongoDB is running on localhost. Replace with your MongoDB Atlas URI if needed.




# get_telethon_client function remains the same
def get_telethon_client(session_name):
    api_id = os.environ.get('TELEGRAM_API_ID')
    api_hash = os.environ.get('TELEGRAM_API_HASH')
    if not api_id or not api_hash:
        raise ValueError("TELEGRAM_API_ID and TELEGRAM_API_HASH environment variables must be set.")
    return TelegramClient(session_name, api_id, api_hash)

# --- NEW ASYNC TELETHON TASKS ---

async def connect_task(session_name, phone):
    """Async wrapper for the initial connection and code request."""
    client = get_telethon_client(session_name)
    await client.connect()
    result=None
    if not await client.is_user_authorized():
        result = await client.send_code_request(phone)
    await client.disconnect()
    return result

async def otp_task(session_name, phone, otp,phone_code_hash):
    """Async wrapper for signing in with an OTP."""
    client = get_telethon_client(session_name)
    await client.connect()
    # sign_in can raise SessionPasswordNeededError, which we'll catch
    await client.sign_in(phone, otp,phone_code_hash=phone_code_hash)
    me = await client.get_me()
    await client.disconnect()
    return me

async def pswd_task(session_name, password):
    """Async wrapper for signing in with a 2FA password."""
    client = get_telethon_client(session_name)
    await client.connect()
    await client.sign_in(password=password)
    me = await client.get_me()
    await client.disconnect()
    return me

# --- Extensions Initialization ---
redis_client = FlaskRedis(app, decode_responses=True)

# --- NEW SOCKETIO LOGIC WITH REDIS ---

@socketio.on('connect_account')
def handle_connect_account(data):
    phone = data['phone']
    username = session.get('username')
    sid = request.sid
    session_name = f"{username}_{phone}"

    redis_client.hset(sid, mapping={'phone': phone, 'session_name': session_name})
    redis_client.expire(sid, 300)

    # Create and run a new asyncio event loop for this task
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        sent_code_result = loop.run_until_complete(connect_task(session_name, phone))
        
        # Save the phone_code_hash to Redis for the next step # <-- CHANGE
        if sent_code_result:
            redis_client.hset(sid, 'phone_code_hash', sent_code_result.phone_code_hash)
            
        emit('request_otp')
    except Exception as e:
        emit('connection_error', {'message': str(e)})
    finally:
        loop.close()

@socketio.on('submit_otp')
def handle_submit_otp(otp):
    sid = request.sid
    state = redis_client.hgetall(sid)
    if not state or 'phone_code_hash' not in state: # <-- CHANGE
        return emit('connection_error', {'message': 'Session expired or invalid state. Please try again.'})

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        me = loop.run_until_complete(otp_task(state['session_name'], state['phone'], otp, state['phone_code_hash']))
        mongo.db.users.update_one(
            {'username': session.get('username')},
            {'$push': {'accounts': {
                'phone': state['phone'], 'user_id': me.id, 'first_name': me.first_name,
                'session_file': f"{state['session_name']}.session", 'status': 'Connected'
            }}}
        )
        emit('connection_success', {'message': f"Successfully connected as {me.first_name}!"})
        redis_client.delete(sid)
    except PhoneCodeInvalidError:
        emit('connection_error', {'message': 'The OTP you entered is invalid.'})
    except SessionPasswordNeededError:
        emit('request_2fa')
    except Exception as e:
        emit('connection_error', {'message': str(e)})
    finally:
        loop.close()

@socketio.on('submit_2fa')
def handle_submit_2fa(password):
    sid = request.sid
    state = redis_client.hgetall(sid)
    if not state:
        return emit('connection_error', {'message': 'Session expired. Please try again.'})

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        me = loop.run_until_complete(pswd_task(state['session_name'], password))
        mongo.db.users.update_one(
            {'username': session.get('username')},
            {'$push': {'accounts': {
                'phone': state['phone'], 'user_id': me.id, 'first_name': me.first_name,
                'session_file': f"{state['session_name']}.session", 'status': 'Connected'
            }}}
        )
        emit('connection_success', {'message': f"Successfully connected as {me.first_name}!"})
    except Exception as e:
        emit('connection_error', {'message': 'Password incorrect or another error occurred.'})
    finally:
        redis_client.delete(sid)
        loop.close()

            
@socketio.on('disconnect')
def handle_disconnect():
    # Clean up Redis state if user disconnects mid-login
    redis_client.delete(request.sid)
# --- Routes ---


@app.route("/")
def landing():
    return render_template('landing.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        if redis_client.exists(f"user:{username}"):
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', form=form)

        hashed_password = generate_password_hash(password)
        
        redis_client.hset(f"user:{username}", mapping={
            'username': username,
            'password': hashed_password
        })
        
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # **MODIFIED LINE**: No need for .decode() here because of decode_responses=True
        stored_password_hash = redis_client.hget(f"user:{username}", "password")

        if stored_password_hash and check_password_hash(stored_password_hash, password):
            session['username'] = username
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
            
    return render_template('login.html', title='Login', form=form)


@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html')


@app.route("/logout")
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route("/accounts", methods=['GET', 'POST'])
def accounts():
    if 'username' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    form = AddAccountForm()
    current_user_username = session['username']
    
    # In MongoDB, we use a 'users' collection.
    # We find the user document or create it if it doesn't exist.
    user_doc = mongo.db.users.find_one_and_update(
        {'username': current_user_username},
        {'$setOnInsert': {'username': current_user_username, 'accounts': []}},
        upsert=True,
        return_document=True
    )

    if form.validate_on_submit():
        # Create a new account as a dictionary
        new_account = {
            'phone': form.phone.data,
            'api_id': form.api_id.data,
            'api_hash': form.api_hash.data
        }
        # Push the new account dictionary into the user's 'accounts' array
        mongo.db.users.update_one(
            {'username': current_user_username},
            {'$push': {'accounts': new_account}}
        )
        flash('Telegram account added successfully!', 'success')
        return redirect(url_for('accounts'))

    # Fetch the user document again to get the latest list of accounts
    updated_user_doc = mongo.db.users.find_one({'username': current_user_username})
    user_accounts = updated_user_doc.get('accounts', [])

    return render_template('accounts.html', title='Account Management', form=form, accounts=user_accounts)

# --- Main Execution ---

if __name__ == '__main__':
    socketio.run(app, debug=True)