from flask import Flask, request, jsonify, url_for, send_from_directory, session
from flask_migrate import Migrate
from flask_session import Session
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, Date
from sqlalchemy.orm import relationship
from flask_cors import CORS, cross_origin
import bcrypt
import os
import re
from PyPDF2 import PdfReader
from fuzzywuzzy import fuzz
from dotenv import load_dotenv
from sqlalchemy import Date
from datetime import datetime
import uuid
import logging
import json_log_formatter
from flask import Flask, request, jsonify, url_for, send_from_directory, session
import redis


class CustomJSONFormatter(json_log_formatter.JSONFormatter):
    def json_record(self, message, extra, record):
        extra['message'] = message
        if 'user_id' in session:
            extra['session_user_id'] = session['user_id']
        return extra

# Configure your Flask app to use this logger
formatter = CustomJSONFormatter()

json_handler = logging.StreamHandler()
json_handler.setFormatter(formatter)

logger = logging.getLogger('my_json')
logger.addHandler(json_handler)
logger.setLevel(logging.INFO)


app = Flask(__name__)
CORS(app, origins='https://mezz-front.vercel.app', supports_credentials=True)
app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql://mezz_zysd_user:Gt2CHYjha4xmzuSPBfe140arqpHVt2kz@dpg-clvc7c5a73kc73bo8a80-a.oregon-postgres.render.com/mezz_zysd'
load_dotenv()
app.config['UPLOAD_FOLDER'] = 'pdfs'
db = SQLAlchemy(app)
app.secret_key = '6de23aa303c89bb1ab31a42a39b419ba3ce26cae8821cfa7c060878c63b827b1'


# Direct Redis Configuration for Testing
# Session configuration for Redis
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_REDIS"] = redis.from_url('redis://default:hPoxtbX6EcPgr36ouAA8DMMsmrMhuPdL@redis-15230.c274.us-east-1-3.ec2.cloud.redislabs.com:15230')
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = False
Session(app)


login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)
# ===================Models==================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer(), primary_key=True, nullable=False, autoincrement=True)
    username = db.Column(db.String(100), unique=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(100))
    address = db.Column(db.String(500))
    mobile_no = db.Column(db.String(100), unique=True)

    # ====Bank details=====
    bank_name = db.Column(db.String(100))
    branch = db.Column(db.String(100))
    ifsc_code = db.Column(db.String(100))
    account_number = db.Column(db.String(100))

    # =====Company details====
    company_name = db.Column(db.String(100))
    tin = db.Column(db.String(100))

    # ====kyc====
    pan_number = db.Column(db.String(100))

    #====Wallet address=====
    metamask_address = db.Column(db.String(100), unique=True, nullable=False)




class Invoice(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer(), ForeignKey('user.id'), nullable=False)
    invoice_id = db.Column(db.String(100))
    total_amount = db.Column(db.Float())
    due_date = db.Column(Date)
    buyer_id = db.Column(db.Integer(), ForeignKey('user.id'), nullable=False)
    buyer_metamask_address = db.Column(db.String(100), ForeignKey('user.metamask_address'), nullable=False)
    pdf_url = db.Column(db.String(200))
    approval_status = db.Column(db.Boolean(), default=False)
    metamask_address = db.Column(db.String(100))

    # Define relationships
    user = relationship('User', foreign_keys=[user_id])
    buyer = relationship('User', foreign_keys=[buyer_id], backref='invoices_as_buyer')
 

     
class SentForApproval(db.Model):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    invoice = db.Column(db.Integer(), db.ForeignKey('invoice.id'), nullable=False)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    buyer_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    buyer_metamask_address = db.Column(db.String(100), db.ForeignKey('user.metamask_address'), nullable=False)# Adding the buyer's metamask address field
    approve_status = db.Column(db.Boolean(), default=False)



@app.route('/')
def hello_world():
    db.create_all()
    return 'Hello, World!'


# ========Register and Login ==================

def authentication_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        return func(*args, **kwargs)

    return wrapper


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function
    

@app.route('/check-auth', methods=['POST'])
def check_auth():
    # Check if the session contains a user_id
    user_id = session.get('user_id')
    logger.info(f"Entire Session Data: {session}")
    logger.info(f"Session ID set to {session.get('user_id')}")
    logger.info(f"Session User ID: {user_id}")

    test_value = session.get('test_key')
    logger.info(f"Test Key Value: {test_value}")

    if user_id:
        # User is authenticated
        logger.info(f"User with session ID {user_id} is authenticated")

        # You can access other session data if needed
        # Example: username stored in the session
        username = session.get('username')

        return jsonify({
            'message': 'Authenticated',
            'user_id': user_id,
            'username': username  # Include any other session data you need
        }), 200
    else:
        # User is not authenticated
        logger.warning("User not authenticated")
        return jsonify({'error': 'Not authenticated'}), 401



@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    confirmPassword = data.get('confirmPassword')
    address = data.get('address')
    mobile_no = data.get('mobile_no')
    bank_name = data.get('bank_name')
    branch = data.get('branch')
    ifsc_code = data.get('ifsc_code')
    account_number = data.get('account_number')
    company_name = data.get('company_name')
    tin = data.get('tin')
    pan_number = data.get('pan_number')
    metamask_address = data.get('metamask_address')

    # Add length validation
    if len(username) > 100 or len(email) > 100 or len(password) > 100:
        return jsonify({'error': 'Field length exceeds the maximum limit'}), 400

    if not (username and first_name and last_name and email and password and address and mobile_no and confirmPassword and bank_name and branch and ifsc_code and account_number and company_name and tin and pan_number and metamask_address):
        return jsonify({'error': 'Missing required fields'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'Username or email already exists'}), 409

    if password != confirmPassword:
        return jsonify({'error': 'Passwords do not match'}), 400

    # Use Flask-Bcrypt for password hashing
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


    new_user = User(
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        address=address,
        mobile_no=mobile_no,
        bank_name=bank_name,
        branch=branch,
        ifsc_code=ifsc_code,
        account_number=account_number,
        company_name=company_name,
        tin=tin,
        pan_number=pan_number,
        metamask_address=metamask_address,
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully!'}), 201


@login_manager.user_loader
def load_user(user_id):
    logger.info(f"user_loader called with user_id: {user_id}")
    user = User.query.get(int(user_id))
    logger.info(f"Loaded user: {user}")
    return user



@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        login_user(user)

        if user.id is not None:
            session['user_id'] = user.id
            session['username'] = user.username  # Set the username in the session
            logger.info(f"Login: Session User ID set to {session.get('user_id')}")
            logger.info(f"User {username} logged in successfully with session ID: {session.get('user_id')}")

            session['test_key'] = 'test_value'

            return jsonify({'message': 'Login successful', 'sessionID': user.id}), 200
        else:
            logger.warning(f"User ID is None after login for username: {username}")
            return jsonify({'error': 'User ID is None'}), 500  # Internal Server Error
    else:
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({'error': 'Invalid username or password'}), 401


    


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    logout_user()
    logger.info(f"Logout: Session User ID after logout {session.get('user_id')}")
    return jsonify({'message': 'Logged out successfully'}), 200



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(session.get('user_id')))


# ============Dashboard part===============

@app.route('/dashboard')
@login_required
def dashboard():
    return 'Welcome to the dashboard!'


# ====== profilepage =============

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            profile_data = {
        'sessionID': user.id,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'address': user.address,
        'mobile_no': user.mobile_no,
        'bank_name': user.bank_name,
        'branch': user.branch,
        'ifsc_code': user.ifsc_code,
        'account_number': user.account_number,
        'company_name': user.company_name,
        'tin': user.tin,
        'pan_number': user.pan_number,
        'metamask_address': user.metamask_address

            }
    return jsonify(profile_data), 200

    '''elif request.method == 'PUT':
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.email = data.get('email', user.email)
        user.address = data.get('address', user.address)
        user.mobile_no = data.get('mobile_no', user.mobile_no)
        user.bank_name = data.get('bank_name', user.bank_name)
        user.branch = data.get('branch', user.branch)
        user.ifsc_code = data.get('ifsc_code', user.ifsc_code)
        user.account_number = data.get('account_number', user.account_number)
        user.company_name = data.get('company_name', user.company_name)
        user.tin = data.get('tin', user.tin)
        user.pan_number = data.get('pan_number', user.pan_number)
        user.metamask_address = data.get('metamask_address', user.metamask_address)

        db.session.commit()

        profile_data = {
            'id': user.id,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'address': user.address,
            'mobile_no': user.mobile_no,
            'bank_name': user.bank_name,
            'branch': user.branch,
            'ifsc_code': user.ifsc_code,
            'account_number': user.account_number,
            'company_name': user.company_name,
            'tin': user.tin,
            'pan_number': user.pan_number,
            'metamask_address': user.metamask_address
        }
        return jsonify(profile_data), 200
'''
# ================Invoice Handling  ==================

def fuzzy_match_field(text, field_options):
    best_match = None
    highest_ratio = 0
    for field_option in field_options:
        ratio = fuzz.partial_ratio(text, field_option)
        if ratio > highest_ratio:
            highest_ratio = ratio
            best_match = field_option
    return best_match


def extract_invoice_fields(ocr_text):
    fields = {}

    field_names = {
        'invoice_id': [
            'invoice number', 'Invoice number', 'invoice no', 'Invoice #', 'Invoice ID', 'invoice ID',
            'Invoice ID:', 'InvoiceID', 'invoice id', 'Invoice No:', 'invoice no:', 'Invoice No.',
            'invoice No.', 'Invoice No', 'invoice No', 'Invoice Num', 'Invoice No ', 'invoice #:',
            'Inv No', 'Invoice Number:', 'Invoice No.:', 'Invoice No :', 'Invoice ID :', 'Invoice # :',
            'Inv. No:', 'Invoice Number:', 'Invoice # ', 'Invoice #:', 'Inv No:', 'Invoice No : -',
            'Invoice Number: -', 'Invoice No -', 'Invoice Number : -',
            'Invoice Serial No:', 'Invoice Serial #', 'Invoice Serial Number', 'Invoice Serial ID',
            'Serial Number:', 'Serial No.', 'Invoice Series:', 'Invoice Serial:',
            'Invoice Reference:', 'Invoice Ref #', 'Invoice Ref ID', 'Invoice Ref:',
            'Invoice Document #', 'Invoice Doc ID', 'Invoice Doc No', 'Invoice Document ID',
            'Invoice Num:', 'Invoice ID #', 'Invoice ID No', 'Invoice Number ID',
            'Invoice No#', 'Invoice ID#', 'Invoice Number#', 'Invoice No.-', 'Invoice ID.-',
        ],
        'total_amount': [
            'total usage charges', 'Total due', 'total amount', 'Total amount : -', 'Total Due:', 'Total Amount :',
            'Total Amt', 'Total: ', 'Total: INR', 'Total Amount INR', 'Total Due', 'Total Amount',
            'Total Charges', 'Invoice Total :', 'Total Amount:', 'Total Amount:', 'Total Charge :',
            'Invoice Amount:', 'Total Amount Due :', 'Total Amount Due:', 'Total Payable Amount',
            'Total Amount Payable:', 'Total Amount Rs.', 'Total Amt (Rs.)', 'Total Amount (INR)',
            'Total Amount (INR):', 'Total Amount (Rs.):', 'Amount Due:', 'Amount:', 'Total:',
            'Total Due :', 'Total Due Rs.', 'Total Amount (Rs)', 'Total Amount (Rs. )',
            'Total Amount in Rs.', 'Total Amount in INR', 'Total Invoice Value', 'Total Invoice Amount',
            'Total Invoice Amt', 'Invoice Total:',
            'Total Cost', 'Total Expense', 'Total Price', 'Total Payment', 'Total Payable', 'Total Receivable',
            'Total Outstanding', 'Total Balance', 'Total Outstanding Amount', 'Total Outstanding Balance',
            'Total Invoice Outstanding', 'Total Invoice Balance', 'Total Amount to Pay', 'Total Amount Due',
            'Invoice Total Amount:', 'Total Amount of Invoice:', 'Total Due Amount:', 'Amount Due -',
            'Total Due for Invoice:', 'Total Due for Payment:', 'Total Invoice Due:',
            'Total Payment Due:', 'Total Amount Due for Invoice:', 'Invoice Amount Due:',
        ],
        'due_date': [
            'payment due on', 'due date', 'due_date', 'Due Date', 'Payment Due Date', 'Due on', 'Due Date:',
            'Due Date :', 'Due Date -', 'Due Date : -', 'Payment Due Date :', 'Due Date : -',
            'Due on Date:', 'Payment Due on Date:', 'Payment Due by Date:', 'Due Date for Payment:',
            'Due Date for Payment:', 'Due Date for Payment :', 'Payment Due Date:', 'Payment Due Date :',
            'Due on or before:', 'Due by', 'Payment Due on or before:', 'Due Date (MM/DD/YYYY)',
            'Due Date (DD/MM/YYYY)', 'Due Date (MM-DD-YYYY)', 'Due Date (DD-MM-YYYY)',
            'Due Date - MM/DD/YYYY', 'Due Date - DD/MM/YYYY', 'Due Date - MM-DD-YYYY',
            'Due Date - DD-MM-YYYY', 'Due Date (YYYY/MM/DD)', 'Due Date (YYYY-DD-MM)',
            'Due Date - YYYY/MM/DD', 'Due Date - YYYY-DD-MM', 'Due Date [MM/DD/YYYY]',
            'Due Date [DD/MM/YYYY]', 'Due Date [MM-DD-YYYY]', 'Due Date [DD-MM-YYYY]',
            'Payment Deadline:', 'Payment Schedule Date', 'Invoice Payment Date', 'Invoice Maturity Date',
            'Payment Due By:', 'Invoice Due By Date', 'Due on or before:', 'Payment Terms:',
            'Due Date - MM/DD/YYYY', 'Due Date - DD/MM/YYYY', 'Due Date - MM-DD-YYYY',
            'Due Date - DD-MM-YYYY', 'Payment Deadline - MM/DD/YYYY', 'Payment Deadline - DD/MM/YYYY',
            'Payment Deadline - MM-DD-YYYY', 'Payment Deadline - DD-MM-YYYY', 'Payment Due By -',
            'Due By -', 'Due By Date -', 'Invoice Due Date:', 'Due Date [MM/DD/YYYY]',
        ],
    }

    for field_key, field_options in field_names.items():
        matched_field_name = fuzzy_match_field(ocr_text.lower(), field_options)
        if matched_field_name:
            regex_pattern = r'(?i){}[: ]*(\S+)'.format(re.escape(matched_field_name))
            match = re.search(regex_pattern, ocr_text)
            if match:
                fields[field_key] = match.group(1)
            else:
                fields[field_key] = None
        else:
            fields[field_key] = None
    return fields


def convert_pdf_to_text(pdf_path):
    text = ''
    with open(pdf_path, 'rb') as pdf_file:
        pdf_reader = PdfReader(pdf_file)
        for pdf_page in pdf_reader.pages:
            text += pdf_page.extract_text()

    return text


@app.route('/upload_invoice', methods=['POST'])
@login_required
def upload_invoice():
    if 'invoice_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    invoice_file = request.files['invoice_file']
    if invoice_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    unique_filename = str(uuid.uuid4()) + '.pdf'

    uploaded_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    invoice_file.save(uploaded_pdf_path)

    extracted_text = convert_pdf_to_text(uploaded_pdf_path)

    invoice_fields = extract_invoice_fields(extracted_text)
    invoice_fields['buyer_metamask_address'] = request.form.get('buyer_metamask_address')

    pdf_url = url_for('uploaded_pdf', filename=unique_filename, _external=True)

    response_data = {
        'pdf_url': pdf_url,
        'invoice_fields': invoice_fields
    }

    return jsonify(response_data), 200


@app.route('/submit_invoice', methods=['POST'])
@login_required
def submit_invoice():
    data = request.get_json()

    user_id = current_user.id
    invoice_id = data.get('invoice_id')
    total_amount = data.get('total_amount')
    due_date_str = data.get('due_date')
    buyer_id = data.get('buyer_id')
    pdf_url = data.get('pdf_url')
    buyer_metamask_address = data.get('buyer_metamask_address')

    if not (invoice_id and total_amount and due_date_str and pdf_url and buyer_id and buyer_metamask_address):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        due_date = datetime.strptime(due_date_str, '%d-%m-%Y').date()  # Update the format here
    except ValueError:
        return jsonify({'error': 'Invalid due_date format. Use dd-mm-yyyy.'}), 400

    new_invoice = Invoice(
        user=user_id,
        invoice_id=invoice_id,
        total_amount=total_amount,
        due_date=due_date,
        buyer_id=buyer_id,
        pdf_url=pdf_url,
        buyer_metamask_address=buyer_metamask_address 
    )

    db.session.add(new_invoice)
    db.session.commit()

    return jsonify({'message': 'Invoice submitted successfully!'}), 201





@app.route('/uploads/<filename>', methods=['GET'])
@login_required
def uploaded_pdf(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)




@app.route('/approved_invoices', methods=['GET'])
@login_required
def approved_invoices():
    user_id = current_user.id 

    invoices = Invoice.query.filter_by(user=user_id).all()

    invoice_data = []
    for invoice in invoices:
        if invoice.approval_status == True:
            approval_status = 'Approved'
        else:
            approval_status = 'Approval Pending'
        if invoice.approval_status == True:
            invoice_list = {
                'id': invoice.id,
                'invoice_id': invoice.invoice_id,
                'total_amount': invoice.total_amount,
                'due_date': invoice.due_date,
                'buyer_id': invoice.buyer_id,
                'pdf_url': invoice.pdf_url,
                'approval_status': approval_status,
                'buyer_metamask_address': invoice.buyer_metamask_address 
            }
            invoice_data.append(invoice_list)
    return jsonify(invoice_data), 200


@app.route('/pending_approval_invoices', methods=['GET'])
@login_required
def pending_approval_invoices():
    user_id = current_user.id 

    invoices = Invoice.query.filter_by(user=user_id).all()

    invoice_data = []
    for invoice in invoices:
        if invoice.approval_status == True:
            approval_status = 'Approved'
        else:
            approval_status = 'Approval Pending'
        if invoice.approval_status == False:
            invoice_list = {
                'id': invoice.id,
                'invoice_id': invoice.invoice_id,
                'total_amount': invoice.total_amount,
                'due_date': invoice.due_date,
                'buyer_id': invoice.buyer_id,
                'pdf_url': invoice.pdf_url,
                'approval_status': approval_status,
                'buyer_metamask_address': invoice.buyer_metamask_address 
            }
            invoice_data.append(invoice_list)
    return jsonify(invoice_data), 200



@app.route('/invoices/<int:invoice_id>', methods=['DELETE'])
def delete_invoice(invoice_id):
    invoice_to_delete = Invoice.query.get(invoice_id)

    if invoice_to_delete:
        pdf_url = invoice_to_delete.pdf_url
        if pdf_url:
            pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(pdf_url))
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
                    app.logger.info(f"Deleted PDF file: {pdf_path}")
                else:
                    app.logger.warning(f"PDF file not found: {pdf_path}")
            except Exception as e:
                app.logger.error(f"Error while deleting PDF file: {pdf_path}, {e}")

        db.session.delete(invoice_to_delete)
        db.session.commit()

        return jsonify({"message": f"Invoice with ID {invoice_id} and its associated PDF have been deleted."}), 200
    else:
        return jsonify({"error": "Invoice not found."}), 404


@app.route('/invoices/pending_approval_pdfs/<int:invoice_id>', methods=['POST'])
def send_for_approval(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    user_id = invoice.user
    buyer_id = invoice.buyer_id
    buyer_metamask_address = invoice.buyer_metamask_address  # Fetch the buyer's metamask address

    if invoice is None:
        return jsonify({'error': 'Invoice not found.'}), 404
    else:
        sent_for_approval = SentForApproval(
            invoice=invoice.id,
            user_id=user_id,
            buyer_id=buyer_id,
            buyer_metamask_address=buyer_metamask_address
        )
        db.session.add(sent_for_approval)
        db.session.commit()
        return jsonify({'message': 'Sent for approval successfully.'}), 200



@app.route('/came_for_approval', methods=['GET'])
@login_required
def came_for_approval():
    user_id = current_user.id
    sent_for_approval_records = SentForApproval.query.filter_by(buyer_id=user_id).all()

    invoices_data = []
    for sent_for_approval_record in sent_for_approval_records:
        if sent_for_approval_record.approve_status == False:
            invoice = Invoice.query.get(sent_for_approval_record.invoice)
            if invoice:
                invoice_details = {
                    'id': invoice.id,
                    'invoice_id': invoice.invoice_id,
                    'total_amount': invoice.total_amount,
                    'due_date': invoice.due_date.strftime('%Y-%m-%d'),
                    'pdf_url': invoice.pdf_url,
                    'buyer_metamask_address': invoice.buyer_metamask_address
                }
                invoices_data.append(invoice_details)

    # Return invoices_data here, whether it's empty or not
    return jsonify(invoices_data)



@app.route('/approve_invoice/<int:invoice_id>', methods=['POST'])
def approve_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    sent_for_approval_row = SentForApproval.query.filter_by(invoice=invoice_id).first()

    if invoice is None or sent_for_approval_row is None:
        return jsonify({"message": "Invoice not found"}), 404

    invoice.approval_status = True
    sent_for_approval_row.approve_status = True
    db.session.commit()
    return jsonify({"message": "Invoice approved successfully"}), 200

@app.route('/tokens', methods=['GET'])
@login_required
def tokens():
    user_id = current_user.id

    # Check if the user (seller) has an approved invoice with the corresponding buyer ID
    approved_invoice = Invoice.query.filter_by(user=user_id, approval_status=True).first()

    if approved_invoice:
        # Allow the seller to access the tokens page
        return jsonify({'message': 'You can access the tokens page now.'}), 200
    else:
        # Deny access and show an error message
        return jsonify({'error': 'Invoice not approved by buyer. Access denied.'}), 403


@app.route('/fetch_invoice_data', methods=['GET'])
@login_required
def fetch_invoice_data():
    user_id = current_user.id
    invoice_id = request.args.get('invoice_id')  # Get the invoice_id from the query parameter

    invoice = Invoice.query.filter_by(user=user_id, invoice_id=invoice_id).first()

    if invoice:
        invoice_data = {
            'id': invoice.id,
            'invoice_id': invoice.invoice_id,
            'total_amount': invoice.total_amount,
            'due_date': invoice.due_date.strftime('%Y-%m-%d'),  # Convert Date to string
            'buyer_id': invoice.buyer_id,
            'pdf_url': invoice.pdf_url,
            'approval_status': 'Approved' if invoice.approval_status else 'Approval Pending',
            'buyer_metamask_address': invoice.buyer_metamask_address
        }
        return jsonify(invoice_data), 200
    else:
        return jsonify({'message': 'Invoice not found'}), 404



@app.route('/validate_mint_tokens', methods=['POST'])
@login_required
def validate_mint_tokens():
    data = request.get_json()
    invoice_amount = data.get('invoice_amount')  # Replace with the correct field name from your frontend
    requested_tokens = data.get('requested_tokens')  # Replace with the correct field name from your frontend

    if invoice_amount is None or requested_tokens is None:
        return jsonify({'valid': False, 'message': 'Missing required fields'}), 400

    if requested_tokens > invoice_amount:
        return jsonify({'valid': False, 'message': 'Requested tokens exceed invoice amount'}), 200
    else:
        return jsonify({'valid': True, 'message': 'Token minting is valid'}), 200


    

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
