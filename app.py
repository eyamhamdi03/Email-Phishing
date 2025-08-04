from flask import Flask, json, redirect, render_template, url_for, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from flask_migrate import Migrate
from model.final import analyze_email, generate_final

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
    probability = db.Column(db.Float, nullable=True)
    final_prediction = db.Column(db.Integer, nullable=True)
    urls = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Email {self.id}>'

@app.route("/", methods=["GET"])
def history():
    emails = Email.query.order_by(Email.date_created.desc()).all()
    return render_template("history.html", emails=emails)

@app.route("/analyze", methods=["POST"])
def analyze():
    email_body = request.form.get("emailBody", "")
    subject = request.form.get("subject", "")
    sender_mail = request.form.get("senderMail", "")
    results = analyze_email(subject, email_body)
    report = generate_final(results)

    new_mail = Email(
        senderMail=sender_mail,
        emailBody=email_body,
        subject=subject,
        detection=results["verdict"],
        report=report,
        final_prediction=results["final_prediction"],  
        probability=results["final_score"],
        urls=json.dumps(results["urls"])
    )
    db.session.add(new_mail)
    db.session.commit()

    # Redirect to results page
    return redirect(url_for('view_email', email_id=new_mail.id))


@app.route('/view/<int:email_id>')
def view_email(email_id):
    email = Email.query.get_or_404(email_id)

    urls = json.loads(email.urls) if email.urls else []

    return render_template(
        'results.html',
        sender=email.senderMail,
        subject=email.subject,
        body=email.emailBody,
        is_fraud=(email.detection == "FRAUDULEUX"),
        probability=email.probability,
        contains_url=(len(urls) > 0),
        urls=urls,
        report=email.report,
        final_prediction=email.final_prediction
    )



@app.route('/delete/<int:email_id>')
def delete_email(email_id):
    email = Email.query.get_or_404(email_id)
    try:
        db.session.delete(email)
        db.session.commit()
        return redirect('/')
    except Exception as e:
        return 'There was an error deleting the email: ' + str(e)
@app.route('/detect')
def detect():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)
