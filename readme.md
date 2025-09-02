# Email Phishing Detection System

A Flask-based web application designed to detect and analyze potentially fraudulent emails. This system allows users to submit emails for analysis, view detection results, and manage email records with a modern, responsive interface.

# Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML, CSS, JavaScript
- **Styling**: DaisyUI + Tailwind CSS
- **Migration**: Flask-Migrate
- **Date Handling**: Python datetime with timezone support

## Project Structure

```
fraud/
├── app.py                 # Main Flask application
├── instance/              # Instance-specific files
├── static/
│   └── css/
│       └── main.css      # Custom CSS with DaisyUI color overrides
├── templates/
│   ├── base.html         # Base template
│   ├── index.html        # Main page with email submission form
│   ├── view_email.html   # Email detail view
│   └── edit_email.html   # Email editing form
└── README.md             # This file
```

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/eyamhamdi03/Email-Phishing.git
   cd Email-Phishing
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install flask flask-sqlalchemy flask-migrate
   ```

4. **Initialize the database**
   ```bash
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

## Usage

1. **Start the application**
   ```bash
   python app.py
   ```

2. **Access the application**
   Open your browser and navigate to `http://localhost:5000`

3. **Submit emails for analysis**
   - Fill in the sender email, subject (optional), and email body
   - Click "Submit for Analysis"

4. **Manage emails**
