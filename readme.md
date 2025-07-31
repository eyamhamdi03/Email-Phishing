# Email Phishing Detection System

A Flask-based web application designed to detect and analyze potentially fraudulent emails. This system allows users to submit emails for analysis, view detection results, and manage email records with a modern, responsive interface.

## Features

- **Email Submission**: Submit emails for fraud detection analysis
- **Email Management**: View, edit, and delete email records
- **Detection Status**: Track analysis results (Safe, Suspicious, Fraud)
- **Modern UI**: Clean interface built with DaisyUI and Tailwind CSS
- **Database Integration**: SQLite database with SQLAlchemy ORM
- **Responsive Design**: Mobile-friendly interface

## Tech Stack

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
   - View submitted emails in the table
   - Click "View" to see detailed information
   - Click "Edit" to modify email details and add detection results
   - Click "Delete" to remove emails from the system

## Database Schema

### Email Model
- `id`: Primary key (Integer)
- `senderMail`: Sender's email address (String, 300 chars)
- `emailBody`: Email content (Text)
- `url`: Associated URL if any (String, 200 chars, optional)
- `detection`: Analysis result (String, 50 chars, optional)
- `notes`: Additional notes (Text, optional)
- `date_created`: Creation timestamp (DateTime with UTC timezone)

## API Endpoints

- `GET /`: Display main page with email submission form and email list
- `POST /`: Submit new email for analysis
- `GET /view/<email_id>`: View detailed email information
- `GET /edit/<email_id>`: Display email editing form
- `POST /edit/<email_id>`: Update email information
- `GET /delete/<email_id>`: Delete email record

## Customization

### Colors
The application uses custom DaisyUI color schemes defined in `static/css/main.css`. You can modify the color variables to match your brand:

```css
:root {
  --p: 210 100% 56%;    /* Primary color */
  --s: 39 100% 50%;     /* Secondary color */
  --a: 134 61% 41%;     /* Accent color */
  /* ... more color definitions */
}
```

### Detection Logic
Currently, the detection status is manually set. To implement automated detection:

1. Add detection algorithms in `app.py`
2. Integrate with ML models or external APIs
3. Update the email submission handler to automatically analyze content

## Development

### Running in Debug Mode
The application runs in debug mode by default when executed directly:
```python
if __name__ == '__main__':
    app.run(debug=True)
```

### Database Migrations
If you modify the database schema:
```bash
flask db init
flask db migrate -m "Description of changes"
flask db upgrade
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

- Input validation for email addresses and content
- SQL injection protection via SQLAlchemy ORM
- CSRF protection (consider adding Flask-WTF)
- Rate limiting for email submissions
- Email content sanitization

## Future Enhancements

- [ ] Machine learning integration for automated detection
- [ ] Email attachment analysis
- [ ] Bulk email processing
- [ ] User authentication and authorization
- [ ] API for external integrations
- [ ] Export functionality (CSV, JSON)
- [ ] Email classification categories
- [ ] Dashboard with analytics

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

- **Developer**: Eyam Hamdi
- **GitHub**: [@eyamhamdi03](https://github.com/eyamhamdi03)
- **Repository**: [Email-Phishing](https://github.com/eyamhamdi03/Email-Phishing)

## Acknowledgments

- Flask framework for the web application structure
- DaisyUI for the component library
- SQLAlchemy for database management
- The open-source community for inspiration and tools