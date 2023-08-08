from flask import flash, url_for
import json
from flask import Flask, render_template, request, redirect, render_template_string, session
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import boto3
import datetime
from botocore.exceptions import NoCredentialsError

app = Flask(__name__)
app.secret_key = "mysecretkey"

# AWS configurations
AWS_ACCESS_KEY = 'AKIA2DJ7OI5U6PR2TPX5'
AWS_SECRET_KEY = '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'
S3_BUCKET_NAME = 'appdemocloud'
LAMBDA_FUNCTION_NAME = 'myfunction'

# RDS configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:password@appdb.cp8kmx9vcwiq.us-east-1.rds.amazonaws.com/appdb'
db = SQLAlchemy(app)

# Define the uploaded_files table model
class UploadedFiles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    upload_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_email = db.Column(db.String(255))
    sent_email = db.Column(db.String(255))

class User(db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY,region_name='us-east-1')
lambda_client = boto3.client('lambda', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY,region_name='us-east-1')

@app.route('/')
def index():
    return render_template("login.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            # For simplicity, setting the user_id in session. Use Flask-Login in a real application.
            session['user_id'] = user.id
            session['sent_email'] = user.email
            return redirect(url_for('upload'))
        else:
            return "Incorrect username or password!"
    return render_template("login.html")


from botocore.exceptions import ClientError

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        new_user = User(username=username, password=password, email=email)
        db.session.add(new_user)
        db.session.commit()

        # Start SES email verification process
        ses_client = boto3.client('ses', region_name='us-east-1',
                                  aws_access_key_id=AWS_ACCESS_KEY,
                                  aws_secret_access_key=AWS_SECRET_KEY)

        try:
            response = ses_client.verify_email_identity(
                EmailAddress=email
            )
        except ClientError as e:
            # Handle any errors that occur.
            return "Email verification failed: " + str(e)
        else:
            flash("User registered successfully! Please verify your email to send mails using SES.")
            return redirect('/login')

    return render_template("register.html")


@app.route('/upload', methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']

        # Initialize SES client
        ses_client = boto3.client('ses', region_name='us-east-1',
                                  aws_access_key_id=AWS_ACCESS_KEY,
                                  aws_secret_access_key=AWS_SECRET_KEY)

        # List all the verified email addresses in your SES
        verified_emails = ses_client.list_verified_email_addresses()["VerifiedEmailAddresses"]

        try:
            s3.upload_fileobj(file, S3_BUCKET_NAME, file.filename)
            file_url = s3.generate_presigned_url('get_object', Params={'Bucket': S3_BUCKET_NAME, 'Key': file.filename}, ExpiresIn=3600)
            sent_from = session.get('sent_email')
            
            emails = request.form.getlist('emails[]')
            
            for email in emails:
                # Check if the email is already verified in SES
                if email not in verified_emails:
                    # Send a verification request for the email
                    ses_client.verify_email_identity(EmailAddress=email)
                    flash(f"A verification request has been sent to {email}. The recipient needs to verify before receiving files.")
                    continue

                # If email is verified, store in the database
                new_file = UploadedFiles(filename=file.filename, user_email=email, sent_email=sent_from)
                db.session.add(new_file)
                db.session.commit()

            # Trigger the Lambda function to send emails
            payload = {
                "emails": [e for e in emails if e in verified_emails],  # Only include verified emails
                "file_link": file_url
            }
            
            response = lambda_client.invoke(
                FunctionName=LAMBDA_FUNCTION_NAME,
                InvocationType='Event',  # To invoke it asynchronously
                Payload=json.dumps(payload)
            )
            
            return "File uploaded! Verification emails were sent to unverified addresses. The file link was sent to verified addresses."

        except NoCredentialsError:
            return "Credentials not available"

    return render_template('upload.html')


if __name__ == '__main__':
    app.run(debug=True)

