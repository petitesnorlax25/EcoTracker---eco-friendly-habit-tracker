from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

import json
from datetime import datetime, timedelta
import uuid
import os
from dotenv import load_dotenv

# Load environment variables from a .env file if present (for local dev)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_eco_friendly_habit_tracker_key')

# Secure session cookies (configure FLASK_SECURE_COOKIES=1 in production)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # Default to insecure for local HTTP dev; set FLASK_SECURE_COOKIES=1 in prod
    SESSION_COOKIE_SECURE=True if os.environ.get('FLASK_SECURE_COOKIES', '0') == '1' else False
)

# Basic security headers
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return resp

DATA_FILE = 'habits.json'
USERS_FILE = 'users.json'
GOAL_FILE = 'goal.json'
HISTORY_FILE = 'habits_history.json'  # New file for habit history

def load_users():
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def load_goal(username):
    try:
        with open(GOAL_FILE, 'r') as f:
            all_goals = json.load(f)
        return all_goals.get(username, {'daily_goal': 1, 'weekly_goal': 7})
    except (FileNotFoundError, json.JSONDecodeError):
        return {'daily_goal': 1, 'weekly_goal': 7}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_habits():
    """Load habits from JSON file"""
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_habits(habits):
    """Save habits to JSON file"""
    with open(DATA_FILE, 'w') as f:
        json.dump(habits, f, indent=2)

def load_habits_history():
    """Load habits history from separate JSON file"""
    try:
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_habits_history(history):
    """Save habits history to separate JSON file"""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def add_to_history(habit_data):
    """Add a habit entry to the history file"""
    history = load_habits_history()
    
    # Add timestamp for when the habit was logged
    habit_entry = {
        **habit_data,
        'logged_at': datetime.now().isoformat(),
        'history_id': str(uuid.uuid4())  # Separate ID for history tracking
    }
    
    history.append(habit_entry)
    save_habits_history(history)
    return habit_entry

def remove_from_history(habit_id, username):
    """Remove a habit entry from history"""
    history = load_habits_history()
    original_length = len(history)
    
    # Remove the habit from history
    history = [h for h in history if not (h.get('id') == habit_id and h.get('username') == username)]
    
    if len(history) < original_length:
        save_habits_history(history)
        return True
    return False
def remove_from_all_habits(habit_id, username):
    """Remove a habit entry from all habits"""
    all_habits = load_habits()
    original_length = len(all_habits)
    
    # Remove the habit from all habits
    all_habits = [h for h in all_habits if not (h.get('id') == habit_id and h.get('username') == username)]

    if len(all_habits) < original_length:
        save_habits(all_habits)  # Fixed: should save to habits.json, not history
        return True
    return False

def create_habit_entry(username, action, date=None, category=None):
    """Create a new habit entry with all required fields"""
    if date is None:
        date = datetime.now().date().isoformat()
    
    new_habit = {
        "id": str(uuid.uuid4()),
        "username": username,
        "action": action.strip(),
        "date": date
    }
    
    # Only add category if it's not empty
    if category and category.strip():
        new_habit["category"] = category.strip()
    
    return new_habit

def validate_habit_data(action, username, habit_id=None):
    """Validate habit data and return error message if invalid"""
    if not action or not action.strip():
        return "Habit action is required"
    
    if not username:
        return "User must be logged in"
    
    if len(action.strip()) > 200:
        return "Habit action is too long (max 200 characters)"
    
    return None  # No errors

def find_habit_by_id(habits_list, habit_id, username):
    """Find a habit by ID and username in a list of habits"""
    for habit in habits_list:
        if habit.get('id') == habit_id and habit.get('username') == username:
            return habit
    return None

def is_ajax_request(request):
    """Check if the request is an AJAX request"""
    return (request.headers.get('Content-Type', '').startswith('multipart/form-data') or 
            request.headers.get('Content-Type', '').startswith('application/json') or
            request.headers.get('X-Requested-With') == 'XMLHttpRequest')

def handle_habit_response(success, message, is_ajax, redirect_url='index'):
    """Handle response for habit operations (AJAX or regular)"""
    if is_ajax:
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
    else:
        flash(message, 'success' if success else 'error')
        return redirect(url_for(redirect_url))

def update_history_entry(habit_id, username, updated_data):
    """Update a habit entry in history"""
    history = load_habits_history()
    
    for habit in history:
        if habit.get('id') == habit_id and habit.get('username') == username:
            # Update the habit data while preserving history metadata
            habit.update({
                'action': updated_data.get('action', habit.get('action')),
                'date': updated_data.get('date', habit.get('date')),
                'category': updated_data.get('category', habit.get('category')),
                'updated_at': datetime.now().isoformat()
            })
            save_habits_history(history)
            return True
    return False

def get_user_history(username, limit=None):
    """Get habit history for a specific user"""
    history = load_habits_history()
    user_history = [h for h in history if h.get('username') == username]
    
    # Sort by date descending, then by logged_at descending
    user_history.sort(key=lambda h: (h.get('date', ''), h.get('logged_at', '')), reverse=True)
    
    if limit:
        return user_history[:limit]
    return user_history

def calculate_user_analytics(username):
    """Calculate analytics data for a specific user using history data"""
    history = load_habits_history()
    
    # Filter current user's habits from history
    user_habits = [h for h in history if h['username'] == username]
    
    # Get current date and calculate date ranges
    today = datetime.now().date()
    week_start = today - timedelta(days=today.weekday())  # Start of current week (Monday)
    month_start = today.replace(day=1)  # Start of current month
    
    # Initialize counters
    habits_today = 0
    habits_this_week = 0
    habits_this_month = 0
    
    # Collect habit dates for streak calculation
    habit_dates = set()
    
    # Count habits for each time period
    for habit in user_habits:
        try:
            habit_date = datetime.strptime(habit['date'], "%Y-%m-%d").date()
            habit_dates.add(habit_date)
            
            if habit_date == today:
                habits_today += 1
            if week_start <= habit_date <= today:
                habits_this_week += 1
            if month_start <= habit_date <= today:
                habits_this_month += 1
        except (ValueError, KeyError):
            continue
    
    # Streak Calculation: count consecutive days with at least one habit
    if habit_dates:
        # Start from today and go backwards
        streak = 0
        current_day = today
        
        # Check if user has habits today, if not start from yesterday
        if today not in habit_dates:
            current_day = today - timedelta(days=1)
        
        while current_day in habit_dates:
            streak += 1
            current_day -= timedelta(days=1)
    else:
        streak = 0
    
    return {
        'habits_today': habits_today,
        'habits_this_week': habits_this_week,
        'habits_this_month': habits_this_month,
        'streak': streak
    }

def get_user_current_habits(username):
    """Get user's current habits from habits.json (for checklist display and CRUD operations)"""
    current_habits = load_habits()
    user_current_habits = [h for h in current_habits if h.get('username') == username]
    return user_current_habits

def get_user_predefined_habits_from_history(username):
    """Get unique habits that the user has logged before from history (for reference only)"""
    history = load_habits_history()
    user_habits = [h for h in history if h['username'] == username]
    
    # Get unique habit names with their most recent category
    unique_habits = {}
    for habit in user_habits:
        action = habit['action']
        if action not in unique_habits:
            unique_habits[action] = {
                'name': action,
                'category': habit.get('category', 'other')
            }
    
    # Convert to list and sort alphabetically
    return sorted(unique_habits.values(), key=lambda x: x['name'])

@app.route('/')
def index():
    username = session.get('username')
    recent_habits = []
    goals = load_goal(username)
    
    # Initialize analytics data
    analytics_data = {
        'habits_today': 0,
        'habits_this_week': 0,
        'habits_this_month': 0,
        'streak': 0
    }
    
    predefined_habits = []
    completed_today = []
    
    if username:
        # Get recent habits from history (last 15 entries) - FOR RECENT ACTIONS SECTION
        recent_habits = get_user_history(username, limit=15)
        
        # Calculate analytics data for the current user
        analytics_data = calculate_user_analytics(username)
        
        # Get current habits from habits.json - FOR CHECKLIST (both display and CRUD)
        current_habits = get_user_current_habits(username)
        
        # Use current habits directly for checklist (not just completion status)
        predefined_habits = current_habits  # These will be the actual habit objects with IDs
        
        # Create completed_today list based on history (more accurate)
        today = datetime.now().date().isoformat()
        user_history_today = [h for h in recent_habits if h.get('date') == today]
        completed_today = [habit['action'] for habit in user_history_today]
    
    return render_template(
        'index.html',
        username=username,
        recent_habits=recent_habits,
        goals=goals,
        current_date=datetime.now().date().isoformat(),
        predefined_habits=predefined_habits,
        completed_today=completed_today,
        # Pass analytics data to template
        **analytics_data
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        users = load_users()

        # Server-side validation
        if not username or len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'error')
            return redirect(url_for('index'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return redirect(url_for('index'))

        if username in users:
            flash('Username already exists.', 'error')
            return redirect(url_for('index'))

        # 🔐 Hash the password before storing
        hashed_password = generate_password_hash(password)
        users[username] = hashed_password
        save_users(users)

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        users = load_users()

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('index'))



@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/edit_profile', methods=['POST'])
def edit_profile():
    if 'username' not in session:
        flash('Please log in to edit your profile.', 'error')
        return redirect(url_for('login'))
    
    current_username = session['username']
    new_username = request.form.get('username', '').strip()
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    
    # Validation
    if not new_username:
        flash('Username is required.', 'error')
        return redirect(url_for('index'))
    
    if not current_password:
        flash('Current password is required to make changes.', 'error')
        return redirect(url_for('index'))
    
    # Load users
    users = load_users()
    
    # Verify current password
    if current_username not in users or not check_password_hash(users[current_username], current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('index'))
    
    # Check if new username is different and already exists
    if new_username != current_username:
        if new_username in users:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('index'))
        
        if len(new_username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return redirect(url_for('index'))
        
        if len(new_username) > 50:
            flash('Username must be less than 50 characters long.', 'error')
            return redirect(url_for('index'))
    
    # Validate new password if provided
    if new_password:
        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'error')
            return redirect(url_for('index'))
        
        if new_password != confirm_password:
            flash('New password and confirmation do not match.', 'error')
            return redirect(url_for('index'))
    
    # Hash the new password if provided, else keep old hashed one
    if new_password:
        password_to_save = generate_password_hash(new_password)
    else:
        password_to_save = users[current_username]

    # If username is changing, update across data
    if new_username != current_username:
        del users[current_username]
        session['username'] = new_username

        # Update habits
        habits = load_habits()
        for habit in habits:
            if habit.get('username') == current_username:
                habit['username'] = new_username
        save_habits(habits)

        # Update history
        history = load_habits_history()
        for habit in history:
            if habit.get('username') == current_username:
                habit['username'] = new_username
        save_habits_history(history)
    
    # Save updated user data
    users[new_username] = password_to_save
    save_users(users)
    
    # Flash message
    if new_username != current_username and new_password:
        flash('Profile updated successfully! Username and password changed.', 'success')
    elif new_username != current_username:
        flash('Profile updated successfully! Username changed.', 'success')
    elif new_password:
        flash('Profile updated successfully! Password changed.', 'success')
    else:
        flash('Profile updated successfully!', 'success')
    
    return redirect(url_for('index'))
@app.route('/log_habit', methods=['GET', 'POST'])
def log_habit():
    if 'username' not in session:
        flash('Please log in to log your habits.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        action = request.form['action']
        date = request.form['date']
        category = request.form.get('category', '').strip()  # Optional field
        username = session['username']
        
        new_habit = {
            "id": str(uuid.uuid4()),  # Generate unique ID for CRUD operations
            "username": username,
            "action": action,
            "date": date
        }
        
        # Only add category if it's not empty
        if category:
            new_habit["category"] = category
        
        # Add to current habits (for today's checklist functionality)
        habits = load_habits()
        habits.append(new_habit)
        save_habits(habits)
        
        # Add to history for permanent tracking
        add_to_history(new_habit)
        
        flash('Habit logged successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('index.html')
@app.route('/delete_habit_from_history', methods=['POST'])
def delete_habit_from_history():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Please log in to delete habits.'}), 401
    
    habit_id = request.form.get('habit_id')
    username = session['username']
    
    if not habit_id:
        return jsonify({'success': False, 'error': 'Missing habit ID.'}), 400
    
    if remove_from_history(habit_id, username):
        #flash('Habit permanently deleted from history.', 'success')
        return jsonify({'success': True, 'message': 'Habit deleted from history!'})
    else:
        flash('Habit not found in history or you do not have permission to delete it.', 'error')
        return jsonify({'success': False, 'error': 'Habit not found in history.'}), 404

@app.route('/delete_habit', methods=['POST'])
def delete_habit():
    if 'username' not in session:
        # Check if this is an AJAX request
        if request.headers.get('Content-Type', '').startswith('multipart/form-data'):
            return jsonify({'success': False, 'error': 'Please log in to delete habits.'}), 401
        flash('Please log in to delete habits.', 'error')
        return redirect(url_for('login'))
    
    habit_id = request.form.get('habit_id')
    username = session['username']
    
    if not habit_id:
        # Check if this is an AJAX request
        if request.headers.get('Content-Type', '').startswith('multipart/form-data'):
            return jsonify({'success': False, 'error': 'Missing habit ID.'}), 400
        flash('Missing habit ID.', 'error')
        return redirect(url_for('index'))
    
    # Remove from current habits ONLY (preserve history for Recent Actions)
    habits = load_habits()
    original_length = len(habits)
    
    habits = [h for h in habits if not (h.get('id') == habit_id and h.get('username') == username)]
    
    if len(habits) < original_length:
        save_habits(habits)
        
        # DO NOT remove from history - keep it for Recent Actions section
        # The history should remain intact to show past habit completions
        
        # Check if this is an AJAX request
        if request.headers.get('Content-Type', '').startswith('multipart/form-data'):
            return jsonify({'success': True, 'message': 'Habit deleted successfully!'})
        flash('Habit deleted successfully!', 'success')
    else:
        # Check if this is an AJAX request
        if request.headers.get('Content-Type', '').startswith('multipart/form-data'):
            return jsonify({'success': False, 'error': 'Habit not found or you do not have permission to delete it.'}), 404
        flash('Habit not found or you do not have permission to delete it.', 'error')
    
    return redirect(url_for('index'))
@app.route('/update_habit', methods=['POST'])
def update_habit():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Please log in to update habits.'}), 401
    
    habit_id = request.form.get('habit_id')
    action = request.form.get('action')
    date = request.form.get('date')  # Optional for checklist updates
    category = request.form.get('category', '').strip()
    username = session['username']
    
    if not habit_id or not action:
        return jsonify({'success': False, 'error': 'Missing required fields.'}), 400
    
    # Update in current habits (habits.json)
    habits = load_habits()
    updated = False
    
    for habit in habits:
        if habit.get('id') == habit_id and habit.get('username') == username:
            habit['action'] = action
            # Only update date if provided (for backward compatibility)
            if date:
                habit['date'] = date
            if category:
                habit['category'] = category
            updated = True
            break
    
    if updated:
        save_habits(habits)
        
        # Also update in history - preserve existing date if not provided
        updated_data = {
            'action': action,
            'category': category
        }
        # Only include date in update if provided
        if date:
            updated_data['date'] = date
            
        update_history_entry(habit_id, username, updated_data)
        
        return jsonify({'success': True, 'message': 'Habit updated successfully!'})
    else:
        return jsonify({'success': False, 'error': 'Habit not found or you do not have permission to update it.'}), 404

@app.route('/update_goal', methods=['POST'])
def update_goal():
    try:
        new_goal = int(request.form['new_goal'])
        goal_type = request.form.get('goal_type', 'weekly')
    except (ValueError, KeyError):
        flash('Invalid goal data.', 'error')
        return redirect(url_for('index'))
    
    # Get current user's username
    username = session.get('username')
    if not username:
        flash('Please log in to update goals.', 'error')
        return redirect(url_for('index'))
    
    # Count user's predefined habits for validation
    predefined_habits_from_history = get_user_predefined_habits_from_history(username)
    habits_count = len(predefined_habits_from_history)
    
    # Validation thresholds
    if goal_type == 'daily':
        max_goal = max(1, habits_count)
        goal_name = 'daily'
    else:
        max_goal = max(7, habits_count * 7)
        goal_name = 'weekly'
    
    if new_goal < 1:
        flash(f'Goal must be at least 1.', 'error')
        return redirect(url_for('index'))
    
    if new_goal > max_goal:
        if goal_type == 'daily':
            flash(f'Daily goal cannot exceed {max_goal} (total habits in your checklist).', 'error')
        else:
            flash(f'Weekly goal cannot exceed {max_goal} ({habits_count} habits × 7 days).', 'error')
        return redirect(url_for('index'))
    
    # Load all user goals
    try:
        with open(GOAL_FILE, 'r') as f:
            all_goals = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        all_goals = {}
    
    # Initialize or update user's goal entry
    if username not in all_goals:
        all_goals[username] = {
            'daily_goal': 1,
            'weekly_goal': 7
        }

    # Update the specific goal
    if goal_type == 'weekly':
        all_goals[username]['weekly_goal'] = new_goal
        flash(f'Weekly goal updated to {new_goal} successfully!', 'success')
    elif goal_type == 'daily':
        all_goals[username]['daily_goal'] = new_goal
        flash(f'Daily goal updated to {new_goal} successfully!', 'success')
    
    # Save updated goal data
    with open(GOAL_FILE, 'w') as f:
        json.dump(all_goals, f, indent=2)
    
    return redirect(url_for('index'))

@app.route('/api/analytics')
def get_analytics():
    """API endpoint to get analytics data for the current user"""
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not authenticated'}), 401
    
    analytics_data = calculate_user_analytics(username)
    return jsonify(analytics_data)

@app.route('/api/habit/<habit_id>')
def get_habit(habit_id):
    """API endpoint to get a specific habit"""
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check both current habits and history
    habits = load_habits()
    history = load_habits_history()
    
    # First check current habits
    for habit in habits:
        if habit.get('id') == habit_id and habit.get('username') == username:
            return jsonify(habit)
    
    # Then check history
    for habit in history:
        if habit.get('id') == habit_id and habit.get('username') == username:
            return jsonify(habit)
    
    return jsonify({'error': 'Habit not found'}), 404
@app.route('/add_custom_habit', methods=['POST'])
def add_custom_habit():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json() or {}
    habit_name = (data.get('habit_name') or '').strip()
    category = (data.get('category') or 'other').strip()
    username = session['username']
    today = datetime.now().date().isoformat()

    # Server-side validation and normalization
    if not habit_name:
        return jsonify({'error': 'Habit name required'}), 400
    if len(habit_name) > 100:
        return jsonify({'error': 'Habit name too long (max 100)'}), 400

    # Restrict category to known values; fallback to 'other'
    allowed_categories = {
        "Energy Saving",
        "Water Conservation",
        "Eco Transport",
        "Waste Reduction",
        "Recycling",
        "Sustainable Food",
        "Reusables & Alternatives",
        "Gardening / Composting",
        "Mindful Consumption",
        "Eco Cleaning Products",
        "Advocacy / Awareness",
        "Sustainable Shopping",
        "Nature & Biodiversity",
        "Other"
    }
    category = category if category in allowed_categories else 'other'

    habits = load_habits()

    # Check if it already exists (case-insensitive, trimmed)
    normalized_name = habit_name.lower()
    if any(h for h in habits if h['username'] == username and h['action'].strip().lower() == normalized_name):
        return jsonify({'error': 'Habit already exists'}), 400

    habit_id = str(uuid.uuid4())

    new_habit = {
        "id": habit_id,
        "username": username,
        "action": habit_name,
        "category": category,
        "date": today
    }

    habits.append(new_habit)
    save_habits(habits)

    # Log first check automatically (optional)
    history = load_habits_history()
    history.append({
        "id": habit_id,
        "username": username,
        "action": habit_name,
        "date": today,
        "category": category,
        "logged_at": datetime.now().isoformat(),
        "history_id": str(uuid.uuid4())
    })
    save_habits_history(history)

    analytics = calculate_user_analytics(username)
    goals = load_goal(username)

    return jsonify({
        'success': True,
        'analytics': analytics,
        'habits_today': analytics['habits_today'],
        'habits_this_week': analytics['habits_this_week'],
        'daily_goal': goals.get('daily_goal', 0),
        'weekly_goal': goals.get('weekly_goal', 0)
    })
@app.route('/toggle_habit', methods=['POST'])
def toggle_habit():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    habit_name = data.get('habit_name')
    username = session['username']
    today = datetime.now().date().isoformat()

    if not habit_name:
        return jsonify({'error': 'Habit name required'}), 400

    habits = load_habits()
    history = load_habits_history()

    # Normalize for comparison
    normalized_name = habit_name.strip().lower()

    # Ensure the habit is in the checklist
    habit = next(
        (h for h in habits if h['username'] == username and h['action'].strip().lower() == normalized_name),
        None
    )
    if not habit:
        return jsonify({'error': 'Habit not found in checklist'}), 404

    habit_id = habit['id']
    category = habit.get('category', 'other')

    # Check if already logged today (case-insensitive match)
    existing_log = next(
        (entry for entry in history
         if entry['username'] == username and
         entry['action'].strip().lower() == normalized_name and
         entry['date'] == today),
        None
    )

    if existing_log:
        # Remove matching log (case-insensitive delete)
        history = [
            entry for entry in history if not (
                entry['username'] == username and
                entry['action'].strip().lower() == normalized_name and
                entry['date'] == today
            )
        ]
        checked = False
    else:
        # Add to history
        new_entry = {
            "id": habit_id,
            "username": username,
            "action": habit_name.strip(),  # preserve original casing
            "category": category,
            "date": today,
            "logged_at": datetime.now().isoformat(),
            "history_id": str(uuid.uuid4())
        }
        history.append(new_entry)
        checked = True

    save_habits_history(history)

    analytics = calculate_user_analytics(username)
    goals = load_goal(username)

    return jsonify({
        'success': True,
        'checked': checked,
        'habits_today': analytics['habits_today'],
        'habits_this_week': analytics['habits_this_week'],
        'habits_this_month': analytics['habits_this_month'],
        'streak': analytics['streak'],
        'daily_goal': goals.get('daily_goal', 0),
        'weekly_goal': goals.get('weekly_goal', 0)
    })

def get_habit_category(habit_name):
    """Automatically categorize habits based on their name"""
    habit_categories = {
        'energy': ['turned off lights', 'unplugged devices', 'used natural light', 'adjusted thermostat', 'air-dried clothes'],
        'water': ['took shorter shower', 'fixed water leak', 'collected rainwater', 'used full dishwasher load', 'turned off tap while brushing'],
        'transport': ['walked instead of driving', 'used public transport', 'biked to work', 'carpooled', 'worked from home'],
        'waste': ['used reusable bag', 'recycled properly', 'composted food scraps', 'avoided single-use plastic', 'repaired instead of replacing'],
        'food': ['ate plant-based meal', 'bought local produce', 'reduced food waste', 'grew own herbs', 'chose organic food'],
        'other': []
    }
    
    habit_lower = habit_name.lower()
    for category, habits in habit_categories.items():
        if any(h in habit_lower for h in habits):
            return category
    return 'other'

@app.route('/get_today_habits')
def get_today_habits():
    """Get habits completed today for the current user (from history for accuracy)"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    username = session['username']
    today = datetime.now().date().isoformat()
    history = load_habits_history()
    
    # Get today's completed habits for this user from history
    today_habits = [
        habit['action'] for habit in history
        if (habit.get('username') == username and
            habit.get('date') == today)
    ]
    
    return jsonify({'completed_habits': today_habits})

@app.route('/api/habit-history')
def get_habit_history_api():
    """API endpoint to get habit history for charts"""
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not authenticated'}), 401

    history = load_habits_history()
    user_habits = [h for h in history if h.get('username') == username]

    ninety_days_ago = datetime.now() - timedelta(days=90)

    chart_data = []
    for habit in user_habits:
        try:
            habit_date = datetime.strptime(habit['date'], "%Y-%m-%d")
            if habit_date >= ninety_days_ago:
                chart_data.append({
                    'date': habit['date'],
                    'action': habit['action'],
                    'category': habit.get('category', 'other')
                })
        except (ValueError, KeyError):
            continue

    return jsonify(chart_data)

@app.route('/healthz')
def healthz():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(debug=debug_mode)