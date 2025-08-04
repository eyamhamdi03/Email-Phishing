from flask import Flask, redirect , render_template , url_for , request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, time, timezone
from flask_migrate import Migrate
from model.final import analyze_email, generate_report

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
    detection = db.Column(db.String(50), nullable=True, default='suspect')
    report = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Email {self.id}>'
@app.route("/", methods=["GET"])
def index():
    emails = Email.query.order_by(Email.date_created.desc()).all()
    return render_template("index.html", emails=emails)

@app.route("/analyze", methods=["POST"])
def analyze():
    email_body = request.form.get("emailBody", "")
    subject = request.form.get("subject", "")
    sender_mail = request.form.get("senderMail", "")

    # Run the prediction
    results = analyze_email(subject, email_body)
    report = generate_report(results)

    # Save to DB
    new_mail = Email(
        senderMail=sender_mail,
        emailBody=email_body,
        subject=subject,
        detection=results["verdict"],
        report=report
    )
    db.session.add(new_mail)
    db.session.commit()

    return render_template(
        "results.html",
        sender=sender_mail,
        subject=subject,
        body=email_body,
        is_fraud=(results["final_prediction"] == 1),
        probability=results["final_score"],
        contains_url=(len(results["urls"]) > 0),
        urls=results["urls"],
        report=report
    )

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

