from flask import Flask, redirect , render_template , url_for , request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, time, timezone
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    senderMail = db.Column(db.String(300), nullable=False)
    emailBody = db.Column(db.Text, nullable=False)
    subject = db.Column(db.String(200), nullable=True)
    detection = db.Column(db.String(50), nullable=True, default='frauduleux')
    notes = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Email {self.id}>'

@app.route('/', methods=['GET','POST'])
def index():
    if request.method == 'POST':
        email_body = request.form.get('emailBody')
        sender_mail = request.form.get('senderMail')
        subject = request.form.get('subject')
        new_mail = Email(senderMail=sender_mail, emailBody=email_body, subject = subject)
        try:
            db.session.add(new_mail)
            db.session.commit()
            return render_template('analyse.html')

        except Exception as e:
            return 'There was an error processing your request: ' + str(e)
    else:
        emails = Email.query.order_by(Email.date_created.desc()).all()
        return render_template('index.html', emails=emails)

@app.route('/view/<int:email_id>')
def view_email(email_id):
    email = Email.query.get_or_404(email_id)
    return render_template('view_email.html', email=email)

@app.route('/delete/<int:email_id>')
def delete_email(email_id):
    email = Email.query.get_or_404(email_id)
    try:
        db.session.delete(email)
        db.session.commit()
        return redirect('/history')
    except Exception as e:
        return 'There was an error deleting the email: ' + str(e)

@app.route("/history")
def history():
    emails = Email.query.order_by(Email.date_created.desc()).all()
    return render_template("history.html", emails=emails)

if __name__ == '__main__':
    app.run(debug=True)


@app.route("/analyze", methods=["POST","GET"])
def analyze():
    email_data = {
        "senderMail": request.form["senderMail"],
        "subject": request.form.get("subject", ""),
        "emailBody": request.form["emailBody"]
    }

    time.sleep(3)

    #result, explanation = analyze_email(email_data["emailBody"])

    return render_template("result.html", email=email_data, result="result", explanation="explanation")

@app.route('/detect')
def detect():
    return render_template("/")
