'''Main Flask app file'''
import os
import re
import time
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from sqlalchemy import text
from passlib.hash import sha256_crypt
from src.init_db import a_session, AES_KEY, CERT_PEM, KEY_PEM
from src.update_db import update_pass, edit_employee_details, log_action
from src.send_mail import send_otp, send_reset
from src.auth_otp import generate_otp
from src.auth_otp import generate_password
from src.access_check import check_permission
from src.run_anon import prepare_and_anon, plot_k, query_anon, analyse_query, drop_col

FLAG_2FA = 1
SSL_FLAG = 1
FLAG_ACCESS_CONTROL = 1

appFlask = Flask(__name__, template_folder='template')
appFlask.config['SECRET_KEY'] = os.urandom(24)

@appFlask.route('/', methods=['POST', 'GET'])
def login():
    """
    Login Function
    """
    error = None
    if request.method == "POST":
        session.pop('user', None)
        session.pop('temp_user', None)

        name = request.form.get("uname")
        password = request.form.get("psw")
        usernamedata=a_session.execute(text("""SELECT email FROM employee
                                           WHERE pgp_sym_decrypt(email,:AES_key) = :email"""),
                                           {"email":name, "AES_key":AES_KEY}).fetchone()
        passworddata=a_session.execute(text("""SELECT pgp_sym_decrypt(acc_password,:AES_key)
                                            FROM employee WHERE 
                                            pgp_sym_decrypt(email,:AES_key) = :email"""),
                                            {"email":name, "AES_key":AES_KEY}).fetchone()
        if usernamedata is None:
            flash("Invalid Account","danger")
            return render_template('login.html')

        for password_data in passworddata:
            if sha256_crypt.verify(password,password_data):
                if FLAG_2FA == 1:
                    session['temp_user'] = name
                    session['otp'], session['otp_time'] = generate_otp()
                    send_otp(session['temp_user'], session['otp'])
                    session['otp_attempts'] = 0
                    return redirect('/verify')
                session['user'] = name
                return redirect(url_for('home'))
            flash("Invalid Account","danger")
            return redirect(url_for('login'))
    session.pop('user', None)
    session.pop('temp_user', None)
    return render_template('login.html', error=error)

@appFlask.route('/verify', methods=['POST', 'GET'])
def auth():
    """
    This function is to verify the OTP given by the user before
    authentication.
    """
    if g.temp_user:
        if request.method=="POST":
            session['otp_attempts'] += 1
            if session['otp_attempts'] >= 4:
                flash("You have tried too many times. A new OTP is sent to you", "danger")
                log_action(a_session, session['temp_user'], "failed OTP >= 4 times")
                return redirect("/resend")

            input_otp = request.form["otp"]
            if time.time() >= session['otp_time']:
                flash("OTP has expired, please request a new one", "danger")
                return redirect("/verify")
            if input_otp == session['otp']:
                session['user'] = session['temp_user']
                log_action(a_session, session['user'], "user logged in")
                return redirect(url_for('home'))

            flash("Wrong OTP, please try again", "danger")
            return redirect("/verify")
        return render_template("verify.html")
    return redirect(url_for('login'))

@appFlask.route("/resend", methods=["POST","GET"])
def resend():
    """
    Function to send new OTP to users after failing to verify their previous OTP
    """
    if g.temp_user:
        session['otp'], session['otp_time'] = generate_otp()
        send_otp(session['temp_user'], session['otp'])
        session['otp_attempts'] = 0
        return redirect("/verify")
    return redirect(url_for('login'))

@appFlask.route('/home', methods=['POST','GET'])
def home():
    """
    Checks if users are authenticate through the session.
    """
    if g.user:
        if request.method == "GET":
            result_role_id = a_session.execute(text("""SELECT role_id FROM employee
                                           WHERE pgp_sym_decrypt(email,:AES_key) = :email"""),
                                           {"email":session['user'], "AES_key":AES_KEY}).fetchone()
            role_id =  result_role_id[0]
            result_role_name = a_session.execute(text("""SELECT pgp_sym_decrypt(role_name,:AES_key)
                                                      FROM emp_role WHERE role_id = :role_id"""),
                                                      {"role_id":role_id,
                                                       "AES_key":AES_KEY}).fetchone()
            session['role_name'] = result_role_name[0]
            result_bank_balance = a_session.execute(text("""SELECT
                                                         pgp_sym_decrypt(bank_balance, :AES_key)
                                                         FROM employee
                                                         WHERE pgp_sym_decrypt(email,:AES_key)
                                                         = :email"""),
                                                         {"email":session['user'],
                                                          "AES_key":AES_KEY}).fetchone()
            session['bank_balance'] = result_bank_balance[0]
            return render_template('home.html', role_name=session['role_name'],
                                   bank_balance=session['bank_balance'],
                                   user=session['user'])
    return redirect(url_for('login'))

@appFlask.route('/loan', methods=['POST','GET'])
def loan():
    """
    For users to see their current loan or access other loan tabs
    """
    if g.user:
        emp_id = a_session.execute(text("""SELECT emp_id FROM
                        employee WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
                        {"email":session['user'], "AES_key":AES_KEY}).fetchone()
        emp_id = emp_id[0]
        loans = a_session.execute(text(
            """SELECT loan_id, emp_id, pgp_sym_decrypt(loan_amt, :AES_key) as amt,
            pgp_sym_decrypt(loan_interest, :AES_key) as interest,
            pgp_sym_decrypt(loan_tenure, :AES_key) as tenure,
            pgp_sym_decrypt(approve_status, :AES_key) as status
            FROM loans WHERE emp_id = :emp_id"""),
            {"AES_key":AES_KEY, "emp_id": emp_id}).fetchall()
        if request.method == "GET":
            return render_template('loan.html', user=session['user'],
                                   role_name=session['role_name'], loans=loans)

    return redirect(url_for('login'))

@appFlask.route('/apply', methods=['POST','GET'])
def apply():
    """
    For users to apply for loans
    """
    if g.user:
        if request.method == "GET":
            return render_template('apply.html', user=session['user'])

        if request.method == "POST":
            # Process the loan application here (e.g., store it in a database).
            loan_id = 1
            max_loan_id = a_session.execute(text("""SELECT MAX(loan_id) FROM loans""")).fetchone()
            if max_loan_id and max_loan_id[0] is not None:
                loan_id = max_loan_id[0] + 1
                loan_id = str(loan_id)
            email = a_session.execute(text("""SELECT pgp_sym_decrypt(email, :AES_key) FROM
                        employee WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
                        {"email":session['user'], "AES_key":AES_KEY}).fetchone()
            emp_id = a_session.execute(text("""SELECT emp_id FROM
                        employee WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
                        {"email":session['user'], "AES_key":AES_KEY}).fetchone()
            emp_id = emp_id[0]
            #emp_id = '2'
            loan_interest = '2%'
            loan_tenure = request.form.get('loan_tenure')
            loan_amt = request.form.get('loan_amount')
            is_valid_inputs = True
            if not (loan_amt.isdigit() and loan_tenure.isdigit() and
                float(loan_amt) >= 0 and float(loan_tenure) >= 0):
                is_valid_inputs = False
                flash("loan amount and loan tenure must be non-negative numbers", "danger")
                return render_template('apply.html', user=session['user'])
            approve_status = 'pending'
            approve_by = 3
            if emp_id == 3:  #loan officer dont ownself apply loan and accept
                approve_by = 2
            if is_valid_inputs:
                a_session.execute(text("""
            INSERT INTO loans (loan_id, emp_id, loan_interest, loan_tenure, 
                                   loan_amt, approve_status, approve_by)
            VALUES (:loan_id, :emp_id, pgp_sym_encrypt(:loan_interest,:AES_key), 
                                   pgp_sym_encrypt(:loan_tenure,:AES_key), 
                                   pgp_sym_encrypt(:loan_amt,:AES_key), 
                                   pgp_sym_encrypt(:approve_status,:AES_key), :approve_by)
        """), {
            "loan_id": loan_id,
            "emp_id": emp_id,
            "loan_interest": loan_interest,
            "loan_tenure": loan_tenure,
            "loan_amt": loan_amt,
            "approve_status": approve_status,
            "approve_by": approve_by,
            "AES_key":AES_KEY
        })
            log_action(a_session, session['user'],
                   "submitted loan application with loan_id: " + str(loan_id))
            a_session.commit()
        # Return a confirmation message
            flash(f"Thank you, {email}! Your loan application of ${loan_amt} is pending approval.")
            return redirect(url_for('home'))
    return redirect(url_for('login'))

@appFlask.route('/approve', methods=['POST','GET'])
def approve():
    """
    For loan officer to approve loans
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1:
            if not check_permission(a_session, session['user'], "approve loan"):
                flash("The approve loan feature is not accessible by you", "danger")
                return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        log_action(a_session, session['user'], "access to loan approve page")
        emp_id = a_session.execute(text("""SELECT emp_id FROM
                        employee WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
                        {"email":session['user'], "AES_key":AES_KEY}).fetchone()
        emp_id = emp_id[0]
        loans = a_session.execute(text(
            """SELECT loan_id, emp_id, pgp_sym_decrypt(loan_amt, :AES_key) as amt,
            pgp_sym_decrypt(loan_interest, :AES_key) as interest,
            pgp_sym_decrypt(loan_tenure, :AES_key) as tenure,
            pgp_sym_decrypt(approve_status, :AES_key) as status FROM loans
            WHERE loans.approve_by = :emp_id"""),{"AES_key":AES_KEY, "emp_id": emp_id}).fetchall()
        if request.method == "GET":
            return render_template('approve.html', user=session['user'],
                                   role_name=session['role_name'], loans=loans)
@appFlask.route('/approve_loan', methods=['POST'])
def approve_loan():
    """
    Function that approves the loan
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1:
            if not check_permission(a_session, session['user'], "approve loan"):
                flash("The approve loan feature is not accessible by you", "danger")
                return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        loan_id = request.form.get("id")

        loan_info = a_session.execute(text(
            """SELECT loan_id, emp_id, pgp_sym_decrypt(loan_amt, :AES_key) as amt,
            pgp_sym_decrypt(loan_interest, :AES_key) as interest,
            pgp_sym_decrypt(loan_tenure, :AES_key) as tenure,
            pgp_sym_decrypt(approve_status, :AES_key) as status 
            FROM loans WHERE loan_id = :loan_id"""),
            {"AES_key":AES_KEY, "loan_id": loan_id}).fetchone()
        emp_id = loan_info.emp_id

        employee = a_session.execute(text("""SELECT emp_id AS emp_id,
                                          pgp_sym_decrypt(salary, :AES_key) AS salary,
                                        pgp_sym_decrypt(bank_balance, :AES_key) AS bank_balance,
                                        pgp_sym_decrypt(total_loan, :AES_key) AS total_loan FROM employee
                                        WHERE emp_id=:id"""),
                                        {"id":emp_id, "AES_key":AES_KEY}).fetchone()
        loan_amt = int(loan_info.amt)
        old_balance = int(employee.bank_balance)
        bank_balance = loan_amt + old_balance
        bank_balance = str(bank_balance)
        a_session.execute(text
                          ("UPDATE employee SET "
                           "bank_balance=pgp_sym_encrypt(:bank_balance, :AES_key) "
                           "WHERE emp_id=:id"),
                        {"bank_balance":bank_balance, "AES_key":AES_KEY, "id":emp_id})

        a_session.execute(text
                          ("UPDATE loans SET approve_status=pgp_sym_encrypt('approved', :AES_key) "
                           "WHERE loan_id=:loan_id"),
                        {"loan_id":loan_id, "AES_key":AES_KEY})
        a_session.commit()
        old_total_loan = int(employee.total_loan)
        new_total_loan = old_total_loan + loan_amt
        new_total_loan = str(new_total_loan)
        a_session.execute(text
                          ("UPDATE employee SET total_loan="
                           "pgp_sym_encrypt(:new_total_loan, :AES_key) "
                           "WHERE emp_id=:id"),
                        {"new_total_loan":new_total_loan, "AES_key":AES_KEY, "id":emp_id})
        print(new_total_loan)
        a_session.commit()
        print(old_balance)
        print(bank_balance)
        log_action(a_session, session['user'], "approved loan id: " + loan_id)
        flash(f'Loan with ID {loan_id} for ${loan_amt} has been approved', 'success')
    return redirect(url_for('approve'))

@appFlask.route('/account', methods=['GET','POST'])
def account():
    """
    Function to allow users to change password.
    """
    if g.user:
        if request.method == "POST":
            old_password = request.form.get("psw1")
            new_password1 = request.form.get("psw2")
            new_password2 = request.form.get("psw3")
            passworddata=a_session.execute(text("""SELECT pgp_sym_decrypt(acc_password, :AES_key)
                                                FROM employee WHERE
                                                pgp_sym_decrypt(email, :AES_key)=:email"""),
                                                {"email":session['user'],
                                                 "AES_key":AES_KEY}).fetchone()
            for password_data in passworddata:
                if sha256_crypt.verify(old_password,password_data):
                    if new_password1 == new_password2:
                        update_pass(a_session, session['user'], new_password1)
                        flash("Password updated!", "danger")
                        log_action(a_session, session['user'], "updated password")
                        return render_template('account.html', role_name=session['role_name'],
                                               user=session['user'])

                    flash("New passwords do not match!","danger")
                    return render_template('account.html', role_name=session['role_name'],
                                           user=session['user'])

                flash("Wrong password!", "danger")
                return render_template('account.html', role_name=session['role_name'],
                                       user=session['user'])
        return render_template('account.html', role_name=session['role_name'],
                               user=session['user'])

    return redirect(url_for('login'))

@appFlask.route('/create', methods=['POST', 'GET'])
def emp_create():
    """
    Checks if user is authenticated and have the relavent
    permissions to create an employee.
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1 and not check_permission(a_session, session['user'], "create"):
            flash("The create employee feature is not accessible by you", "danger")
            return render_template('home.html', role_name=session['role_name'],
                                   bank_balance=session['bank_balance'],
                                   user=session['user'])
        if request.method == "GET":
            log_action(a_session, session['user'],
                "access to create employee feature") # user pressed the "create employee" button
            return render_template('create.html', role_name=session['role_name'],
                                   user=session['user'])
        # if post:
        emp_id = 1
        max_emp_id = a_session.execute(text("""SELECT MAX(emp_id) FROM employee""")).fetchone()
        if max_emp_id and max_emp_id[0] is not None:
            emp_id = max_emp_id[0] + 1
        emp_id = str(emp_id)
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        acc_password = sha256_crypt.hash("test")  # Include 'test' password
        date_of_birth = request.form.get("date_of_birth")
        phone_number = request.form.get("phone_number")
        role_id = request.form.get("role_id")
        salary = request.form.get("salary")
        bank_account = request.form.get("bank_account")
        bank_balance = request.form.get("bank_balance")
        is_valid_inputs = True
        if not (salary.isdigit() and bank_balance.isdigit() and
                float(salary) >= 0 and float(bank_balance) >= 0):
            is_valid_inputs = False
            flash("Salary and bank balance must be non-negative numbers", "danger")
            return render_template('create.html', role_name=session['role_name'],
                                   user=session['user'])
        if not re.match(r'^\S+@\S+\.\S+$', email):
            is_valid_inputs = False
            flash("Invalid email format", "danger")
            return render_template('create.html', role_name=session['role_name'],
                                   user=session['user'])
        # Working test: a_session.execute(text("""INSERT INTO employee VALUES (2,
        # 'testemp@empsyn.com', '$5$rounds=535000$m5iIfKnBP/wB.kj.$B.hFL3iNBOyXhJtzkjM
        # qY.56aUEfwqsrgDx1CLKKeT8', 'john', 'doe', '1998-10-10', '91231234', 1, 3000,
        # '555551122', 2000);"""))
        if is_valid_inputs:
            a_session.execute(text("""INSERT INTO employee VALUES
                                   (:emp_id ,pgp_sym_encrypt(:email,:AES_key),
                                   pgp_sym_encrypt(:acc_password,:AES_key),
                                   pgp_sym_encrypt(:first_name,:AES_key), 
                                   pgp_sym_encrypt(:last_name,:AES_key),
                                   pgp_sym_encrypt(:date_of_birth,:AES_key),
                                   pgp_sym_encrypt(:phone_number,:AES_key),
                                   :role_id, pgp_sym_encrypt(:salary,:AES_key), 
                                   pgp_sym_encrypt(:bank_account,:AES_key),
                                   pgp_sym_encrypt(:bank_balance,:AES_key));"""),
                                   {"emp_id":emp_id,
                                    "email":email,
                                    "acc_password":acc_password,
                                    "first_name":first_name,
                                    "last_name":last_name,
                                    "date_of_birth":date_of_birth,
                                    "phone_number":phone_number,
                                    "role_id":role_id,
                                    "salary":salary,
                                    "bank_account":bank_account,
                                    "bank_balance":bank_balance,
                                    "AES_key":AES_KEY})
            a_session.commit()
            log_action(a_session, session['user'], "created account with emp_id: "
                        + emp_id + " and role id: " + role_id)
            flash("Employee creation successful")
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@appFlask.route('/reset', methods=['POST','GET'])
def reset():
    """
    Function to allow users to reset their password
    by checking if original user exists.
    """
    if request.method == "POST":
        name = request.form.get("uname")
        usernamedata=a_session.execute(text("""SELECT pgp_sym_decrypt(email, :AES_key) FROM employee
                                           WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
                                           {"email":name, "AES_key":AES_KEY}).fetchone()

        if usernamedata is None:
            flash("Invalid Username","danger")
            return render_template('reset.html')

            # send email
        new_password = generate_password(16)
        update_pass(a_session, name, new_password)
        send_reset(name, new_password)

        flash("New password sent to your email!","danger")
        return render_template('reset.html')

    return render_template('reset.html')

@appFlask.route('/logout', methods=['GET'])
def logout():
    """
    Function to allow users to logout of their account safely
    """
    if g.user:
        log_action(a_session, session['user'], "logged out")
        session.pop('user', None)
        session.pop('role_name', None)
        session.pop('bank_balance', None)
    return redirect('/')

@appFlask.before_request
def before_request():
    """
    Function to check if users are authenticated through sessions.
    """
    g.user = None
    if 'user' in session:
        g.user = session['user']
    g.temp_user = None
    if 'temp_user' in session:
        g.temp_user = session['temp_user']

@appFlask.route('/payroll', methods=['POST','GET'])
def payroll():
    """
    Function to authenticate and showcase all employees salary and
    provides the action to issue pay.
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1:
            if not check_permission(a_session, session['user'], "issue_pay"):
                flash("The payroll feature is not accessible by you", "danger")
                return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        users = a_session.execute(text(
            """SELECT emp_id, pgp_sym_decrypt(first_name, :AES_key) as first_name,
            pgp_sym_decrypt(last_name, :AES_key) as last_name,
            pgp_sym_decrypt(email, :AES_key) as email,
            pgp_sym_decrypt(salary, :AES_key) as salary FROM employee"""),
            {"AES_key":AES_KEY}).fetchall()
        if request.method == "GET":
            log_action(a_session, session['user'], "access to payroll page")
            return render_template('payroll.html', user=session['user'],
                                   role_name=session['role_name'], users=users)

    return redirect(url_for('home'))

@appFlask.route('/issue_pay', methods=['POST'])
def issue_payroll():
    """
    Function to implement issuing of pay to employees selected.
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1:
            if not check_permission(a_session, session['user'], "issue_pay"):
                flash("The issue pay feature is not accessible by you", "danger")
                return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        e_id = request.form.get("id")
        employee = a_session.execute(text("""SELECT emp_id AS emp_id,
                                          pgp_sym_decrypt(salary, :AES_key) AS salary,
                                          pgp_sym_decrypt(bank_balance, :AES_key) AS
                                          bank_balance FROM employee WHERE
                                          emp_id=:id"""),
                                          {"id":e_id, "AES_key":AES_KEY}).fetchone()
        salary = employee.salary
        bank_balance = float(employee.bank_balance)
        bank_balance += float(salary)
        a_session.execute(text("""UPDATE employee SET
                               bank_balance=pgp_sym_encrypt(:bank_balance, :AES_key)
                               WHERE emp_id=:id"""),
                               {"bank_balance":str(bank_balance), "AES_key":AES_KEY, "id":e_id})
        log_action(a_session, session['user'], "issued payroll for emp_id: " + e_id)
        a_session.commit()
    return redirect(url_for('payroll'))


@appFlask.route('/invest_routes', methods=['POST','GET'])
def invest_routes():
    """
    Function to authenticate and showcase investment dashboard
    """
    if g.user:
        if request.method == "GET":
            return render_template('invest_routes.html', role_name=session['role_name'],
                                   user=session['user'])

    return redirect(url_for('home'))

@appFlask.route('/invest', methods=['POST','GET'])
def invest():
    """
    Function to authenticate and showcase investment dashboard
    """
    if g.user:
        users = a_session.execute(text(
            """SELECT emp_id, pgp_sym_decrypt(first_name, :AES_key) as first_name,
            pgp_sym_decrypt(last_name, :AES_key) as last_name,
            pgp_sym_decrypt(email, :AES_key) as email,
            pgp_sym_decrypt(salary, :AES_key) as salary FROM employee"""),
            {"AES_key":AES_KEY}).fetchall()

        current_user=a_session.execute(text("""SELECT emp_id,email FROM employee
                                           WHERE pgp_sym_decrypt(email,:AES_key) = :email"""),
                                           {"email":session["user"], "AES_key":AES_KEY}).fetchone()
        emp_id = current_user.emp_id

        current_user_investments = a_session.execute(text(
            """SELECT investment_id, emp_id, stock_id, 
            pgp_sym_decrypt(quantity, :AES_key) as quantity,
            pgp_sym_decrypt(stock_price, :AES_key) as stock_price, 
            purchase_time, 
            pgp_sym_decrypt(approve_status, :AES_key) as approve_status FROM 
            investments WHERE emp_id=:emp_id"""),
            {"AES_key":AES_KEY, "emp_id":emp_id}).fetchall()

        stocks = a_session.execute(text(
            """SELECT stock_id, pgp_sym_decrypt(stock_name, :AES_key) as stock_name,
            pgp_sym_decrypt(curr_price, :AES_key) as curr_price FROM stocks"""),
            {"AES_key":AES_KEY}).fetchall()

        if request.method == "GET":
            return render_template('invest.html', user=session['user'],
                                   role_name=session['role_name'],
                                   users=users, stocks=stocks,
                                   current_user_investments=current_user_investments)

    return redirect(url_for('home'))

@appFlask.route('/purchase_stock', methods=['POST'])
def purchase_stock():
    """
    Function to implement stock purchase request by employee.
    """
    if g.user:
        e_stock_id = int(request.form.get("stock_id"))
        e_quantity = int(request.form.get("quantity"))
        if e_quantity <= 0:
            flash("Quantity must be > 0", "danger")
            return redirect(url_for('invest'))

        stock =  a_session.execute(text(
            """SELECT stock_id, pgp_sym_decrypt(stock_name, :AES_key) as stock_name,
            pgp_sym_decrypt(curr_price, :AES_key) as curr_price FROM
            stocks WHERE stock_id=:stock_id"""),
            {"AES_key":AES_KEY, "stock_id":e_stock_id}).fetchone()

        print("user is purchasing the following stock: ")
        print(stock)
        curr_user = a_session.execute(text("""SELECT emp_id, email,
                                           pgp_sym_decrypt(bank_balance,:AES_key)
                                           as bank_balance,
                                           pgp_sym_decrypt(total_invest,:AES_key)
                                           as total_invest FROM employee
                                           WHERE pgp_sym_decrypt(email,:AES_key)
                                           = :email"""),
                                           {"email":session["user"],
                                           "AES_key":AES_KEY}).fetchone()
        curr_user_bank_balance = int(curr_user.bank_balance)
        curr_user_total_invest = int(curr_user.total_invest)
        print(curr_user)
        total_price = e_quantity * int(stock.curr_price)
        # the employee should request for a loan if balance<=0.
        # loan->add bank_balance->buy stock. can't overdraft directly.
        if curr_user_bank_balance <= 0:
            flash("Your bank_balance is empty. Overdraft?", "danger")
            return redirect(url_for('invest'))
        if curr_user_bank_balance < total_price:
            flash("Your bank_balance is insufficient.", "danger")
            return redirect(url_for('invest'))

        curr_user_new_balance = curr_user_bank_balance - total_price
        curr_user_new_balance = str(curr_user_new_balance)
        curr_user_total_invest = curr_user_total_invest + total_price
        curr_user_total_invest = str(curr_user_total_invest)

        a_session.execute(text("""UPDATE employee SET
                               bank_balance=pgp_sym_encrypt(:bank_balance, :AES_key)
                               WHERE pgp_sym_decrypt(email,:AES_key) = :email"""),
                               {"email":session["user"], "bank_balance":curr_user_new_balance,
                                "AES_key":AES_KEY})
        a_session.execute(text("""UPDATE employee SET
                               total_invest=pgp_sym_encrypt(:total_invest, :AES_key)
                               WHERE pgp_sym_decrypt(email,:AES_key) = :email"""),
                               {"email":session["user"], "total_invest":curr_user_total_invest,
                                "AES_key":AES_KEY})
        #print(update_success)
        a_session.execute(text("""INSERT INTO investments
                               (emp_id, stock_id, quantity, stock_price, approve_status)
                               VALUES (:emp_id, :stock_id, pgp_sym_encrypt(:quantity,:AES_key),
                               pgp_sym_encrypt(:stock_price,:AES_key),
                               pgp_sym_encrypt(:approve_status,:AES_key));"""),
                               {"emp_id": curr_user.emp_id, "stock_id": stock.stock_id,
                                "quantity":str(e_quantity), "stock_price":str(stock.curr_price),
                                "approve_status":'Waiting', "AES_key": AES_KEY})

        log_action(a_session, session['user'], "request to purchase stock : " + str(e_stock_id))
        a_session.commit()

        return redirect(url_for('invest'))


    return redirect(url_for('home'))

@appFlask.route('/sell_stock', methods=['POST'])
def sell_stock():
    """
    Function to implement selling stock request by employees.
    """
    if g.user:
        e_stock_id = int(request.form.get("stock_id"))
        e_quantity = int(request.form.get("quantity"))
        if e_quantity <= 0:
            flash("Quantity must be > 0", "danger")
            return redirect(url_for('invest'))
        # check to see if the user has sufficient quantity of the stock to sell
        curr_user = a_session.execute(text("""SELECT emp_id, email,
                                    pgp_sym_decrypt(bank_balance,:AES_key)
                                    as bank_balance,
                                    pgp_sym_decrypt(total_invest,:AES_key)
                                    as total_invest FROM employee
                                    WHERE pgp_sym_decrypt(email,:AES_key)
                                    = :email"""),
                                    {"email":session["user"],
                                    "AES_key":AES_KEY}).fetchone() 
        emp_id = curr_user.emp_id
        # when calculating quantity, take into account
        # Buy(Approved) and Sell(Waiting/Approved) ones - ignore Buy(Waiting)
        # and Declined (because the transaction would have been reversed already)
        approved_buys_and_sells_for_stock =  a_session.execute(text(
                """SELECT investment_id, emp_id, stock_id,
                pgp_sym_decrypt(quantity, :AES_key) as quantity,
                pgp_sym_decrypt(approve_status, :AES_key) as approve_status FROM investments 
                WHERE emp_id=:emp_id AND stock_id=:stock_id 
                AND pgp_sym_decrypt(approve_status, :AES_key) = 'Approved' """),
                {"AES_key":AES_KEY, "emp_id":emp_id, "stock_id":e_stock_id}).fetchall()
        waiting_for_stock =  a_session.execute(text(
                """SELECT investment_id, emp_id, stock_id,
                pgp_sym_decrypt(quantity, :AES_key) as quantity,
                pgp_sym_decrypt(approve_status, :AES_key) as approve_status FROM investments
                WHERE emp_id=:emp_id AND stock_id=:stock_id
                AND pgp_sym_decrypt(approve_status, :AES_key) = 'Waiting' """),
                {"AES_key":AES_KEY, "emp_id":emp_id, "stock_id":e_stock_id}).fetchall()
        print(approved_buys_and_sells_for_stock)
        quantity_available_by_user = 0
        for user_investment in approved_buys_and_sells_for_stock:
            print("user_investment Buy/Sell(Approved): ")
            print(user_investment)
            print("--------------------")
            quantity_available_by_user = quantity_available_by_user + int(user_investment.quantity)
        # to check if it is a sell, quantity < 0
        print(waiting_for_stock)
        for user_investment in waiting_for_stock:
            # we are only looking for Sell(Waiting)
            if int(user_investment.quantity) >= 0:
                continue
            print("user_investment Sell(Waiting) : ")
            print(user_investment)
            print("--------------------")
            quantity_available_by_user = quantity_available_by_user + int(user_investment.quantity)
        print("quantity_available_by_user = " + str(quantity_available_by_user))
        if quantity_available_by_user < e_quantity:
            flash("You do not have sufficient quantity left of this stock to sell.", "danger")
            return redirect(url_for('invest'))
        stock =  a_session.execute(text(
            """SELECT stock_id, pgp_sym_decrypt(stock_name, :AES_key) as stock_name,
            pgp_sym_decrypt(curr_price, :AES_key) as curr_price
            FROM stocks WHERE stock_id=:stock_id"""),
            {"AES_key":AES_KEY, "stock_id":e_stock_id}).fetchone()
        print("user is selling the following stock: ")
        print(stock)
        
        curr_user_bank_balance = int(curr_user.bank_balance)
        curr_user_total_invest = int(curr_user.total_invest)
        print(curr_user)
        total_price = e_quantity * int(stock.curr_price)
        curr_user_new_balance = curr_user_bank_balance + total_price
        curr_user_new_balance = str(curr_user_new_balance)
        curr_user_total_invest = curr_user_total_invest - total_price
        curr_user_total_invest = str(curr_user_total_invest)
        a_session.execute(text("""UPDATE employee SET bank_balance=
                               pgp_sym_encrypt(:bank_balance, :AES_key)
                               WHERE pgp_sym_decrypt(email,:AES_key) = :email"""),
                               {"email":session["user"], "bank_balance":curr_user_new_balance,
                               "AES_key":AES_KEY})
        a_session.execute(text("""UPDATE employee SET total_invest=
                               pgp_sym_encrypt(:total_invest, :AES_key)
                               WHERE pgp_sym_decrypt(email,:AES_key) = :email"""),
                               {"email":session["user"], "total_invest":curr_user_total_invest,
                                "AES_key":AES_KEY})
        a_session.execute(text("""
                    INSERT INTO investments (emp_id, stock_id, quantity, stock_price, approve_status) 
                    VALUES (:emp_id, :stock_id, pgp_sym_encrypt(:quantity,:AES_key), 
                    pgp_sym_encrypt(:stock_price,:AES_key), pgp_sym_encrypt(:approve_status,:AES_key));
        """), {
        "emp_id": curr_user.emp_id,
        "stock_id": stock.stock_id,
        "quantity":"-"+str(e_quantity), # remember to put it as -1, -10, -12 quantity...
        "stock_price":str(stock.curr_price),
        "approve_status":'Waiting',
        "AES_key": AES_KEY})
        log_action(a_session, session['user'], "request to sell stock : " + str(e_stock_id))
        a_session.commit()
        return redirect(url_for('invest'))
    return redirect(url_for('home'))

@appFlask.route('/invest_manage', methods=['POST','GET'])
def invest_manage():
    """
    Function to authenticate and showcase investment management dashboard
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1:
            if not check_permission(a_session, session['user'], "manage_invest"):
                flash("The investment feature is not accessible by you", "danger")
                return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        investments = a_session.execute(text("""SELECT investment_id, emp_id, stock_id,
                                             pgp_sym_decrypt(quantity, :AES_key) as quantity,
                                             pgp_sym_decrypt(stock_price, :AES_key) as stock_price,
                                             purchase_time,
                                             pgp_sym_decrypt(approve_status, :AES_key)
                                             as approve_status 
                                             FROM investments 
                                             WHERE pgp_sym_decrypt
                                             (approve_status, :AES_key)='Waiting' """),
                                             {"AES_key":AES_KEY}).fetchall()
        stocks = a_session.execute(text(
            """SELECT stock_id, pgp_sym_decrypt(stock_name, :AES_key) as stock_name,
            pgp_sym_decrypt(curr_price, :AES_key) as curr_price FROM stocks"""),
            {"AES_key":AES_KEY}).fetchall()
        if request.method == "GET":
            log_action(a_session, session['user'], "access to investment management dashboard")
            return render_template('invest_manage.html', user=session['user'],
                                   role_name=session['role_name'],
                                   stocks=stocks, investments=investments)
    return redirect(url_for('home'))

@appFlask.route('/update_investment', methods=['POST'])
def update_investment():
    """
    Function to update investment approval status
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1:
            if not check_permission(a_session, session['user'], "manage_invest"):
                flash("The investment dashboard feature is not accessible by you", "danger")
                return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        e_investment_id = int(request.form.get("investment_id"))
        e_action = request.form.get("action")
        approval_status = 'Waiting'
        if e_action == 'approve':
            approval_status = 'Approved'
        elif e_action == 'decline':
            approval_status = 'Declined'
        else:
            flash("Invalid action", "danger")
            return redirect(url_for('invest_manage'))
        a_session.execute(text("""UPDATE investments SET approve_status=
                               pgp_sym_encrypt(:approve_status, :AES_key) WHERE investment_id
                               = :investment_id"""), {"investment_id":str(e_investment_id),
                                "approve_status":approval_status, "AES_key":AES_KEY})
        ### If the investment is declined, reverse the transaction - mainly the bank_balance
        if approval_status == 'Declined':
            investment =  a_session.execute(text("""SELECT investment_id, emp_id, stock_id,
                                                 pgp_sym_decrypt(quantity, :AES_key) as quantity,
                                                 pgp_sym_decrypt(stock_price, :AES_key)
                                                 as stock_price, purchase_time,
                                                 pgp_sym_decrypt(approve_status, :AES_key)
                                                 as approve_status FROM investments
                                                 WHERE investment_id=:investment_id """),
                                                 {"AES_key":AES_KEY,
                                                  "investment_id":e_investment_id}).fetchone()
            total_value = int(investment.quantity) * int(investment.stock_price)
            curr_user = a_session.execute(text("""SELECT emp_id, email,
                                               pgp_sym_decrypt(bank_balance,:AES_key)
                                               as bank_balance,
                                               pgp_sym_decrypt(total_invest,:AES_key)
                                               as total_invest FROM employee
                                               WHERE pgp_sym_decrypt(email,:AES_key)
                                               = :email"""), {"email":session["user"],
                                                "AES_key":AES_KEY}).fetchone()       
            curr_user_bank_balance = int(curr_user.bank_balance)
            curr_user_new_balance = curr_user_bank_balance + total_value
            curr_user_new_balance = str(curr_user_new_balance)
            curr_user_total_invest = int(curr_user.total_invest)
            curr_user_total_invest = curr_user_total_invest - total_value
            curr_user_total_invest = str(curr_user_total_invest)
            print("/update_investment: new bank_balance is " + curr_user_new_balance)
            a_session.execute(text("""UPDATE employee SET bank_balance=
                                   pgp_sym_encrypt(:bank_balance, :AES_key)
                                   WHERE pgp_sym_decrypt(email,:AES_key)
                                   = :email"""), {"email":session["user"],
                                   "bank_balance":curr_user_new_balance,
                                   "AES_key":AES_KEY})
            a_session.execute(text("""UPDATE employee SET total_invest
                                   =pgp_sym_encrypt(:total_invest, :AES_key)
                                   WHERE pgp_sym_decrypt(email,:AES_key)
                                   = :email"""), {"email":session["user"],
                                   "total_invest":curr_user_total_invest,
                                   "AES_key":AES_KEY})
            print(curr_user_total_invest)
        ### If the investment is declined, reverse the transaction - mainly the bank_balance
        log_action(a_session, session['user'], "updated approval status for investment_id: "
                   + str(e_investment_id) + " to " + approval_status)
        a_session.commit()
        return redirect(url_for('invest_manage'))
    return redirect(url_for('home'))

@appFlask.route('/edit', methods=['POST','GET'])
def edit():
    """
    Function to allow an authenticated employee to edit a user's
    employee information.
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1 and not check_permission(a_session, session['user'], "edit"):
            flash("The edit employee feature is not accessible by you", "danger")
            return render_template('home.html', role_name=session['role_name'],
                                   bank_balance=session['bank_balance'],
                                   user=session['user'])
        if request.method == "POST":
            edit_employee_details(session, a_session)
            return render_template('edit.html', role_name=session['role_name'],
                                   user=session['user'])
        log_action(a_session, session['user'], "access to edit feature")
        return render_template('edit.html', role_name=session['role_name'],
                               user=session['user'])
    return redirect(url_for('login'))

@appFlask.route('/log', methods=['GET'])
def log():
    """
    Function to allow an authenticated user to view logs and store these
    logs in the database.
    """
    if g.user:
        if FLAG_ACCESS_CONTROL == 1 and not check_permission(a_session, session['user'], "log"):
            flash("The log feature is not accessible by you", "danger")
            return render_template('home.html', role_name=session['role_name'],
                                   bank_balance=session['bank_balance'],
                                   user=session['user'])
        log_action(a_session, session['user'], "access to logs page")
        logs = a_session.execute(
            text("""SELECT log_id, emp_id,
                 pgp_sym_decrypt(exec_operation, :AES_key) as exec_operation, 
                 log_timestamp FROM log_history lh ORDER BY lh.log_id DESC"""),
                 {"AES_key":AES_KEY}).fetchall()
        return render_template('log.html', user=session['user'],
                               role_name=session['role_name'], logs=logs)
    return redirect(url_for('login'))

@appFlask.route('/anon', methods=['GET', 'POST'])
def anonymise():
    '''
    Function for anonymization page
    '''
    if g.user:
        if FLAG_ACCESS_CONTROL == 1 and not check_permission(a_session, session['user'], "anon"):
            flash("The Anonymization feature is not accessible by you", "danger")
            return render_template('home.html', role_name=session['role_name'],
                                   bank_balance=session['bank_balance'],
                                   user=session['user'])
        if request.method == 'POST':
            k_value = request.form.get("k_value")
            session['k_value']=k_value
            return redirect(url_for('anon_result'))
        log_action(a_session, session['user'], "access to anonymization page")
        return render_template('anon.html', user=session['user'])
    return redirect(url_for('login'))

@appFlask.route('/analysis', methods=['GET'])
def show_graph():
    '''
    Function for anonymization analysis page
    '''
    if g.user:
        if FLAG_ACCESS_CONTROL == 1 and not check_permission(a_session, session['user'], "anon"):
            flash("The Anonymization feature is not accessible by you", "danger")
            return render_template('home.html', role_name=session['role_name'],
                                   bank_balance=session['bank_balance'], user=session['user'])
        plot_k()
        return render_template("analysis.html", user=session['user'])
    return redirect(url_for('login'))

@appFlask.route('/anon_result', methods=['GET', 'POST'])
def anon_result():
    '''
    Function for anonymization result page
    '''
    if g.user:
        if FLAG_ACCESS_CONTROL == 1 and not check_permission(a_session, session['user'],"anon"):
            flash("The Anonymization feature is not accessible by you", "danger")
            return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        results = prepare_and_anon(int(session['k_value']))
        return render_template('anon_result.html', user=session['user'], results=drop_col(results),
                                   k_value=session['k_value'])
    return redirect(url_for('login'))

@appFlask.route('/anon_result/query', methods=['GET', 'POST'])
def query():
    '''
    Function for query anon result
    '''
    if g.user:
        if FLAG_ACCESS_CONTROL == 1 and not check_permission(a_session, session['user'],"anon"):
            flash("The Anonymization feature is not accessible by you", "danger")
            return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        if request.method=='POST':
            q_value = request.form.get("q_value")
            session['q_value'] = q_value
            return redirect(url_for('query_result'))
        return render_template('query.html')
    return redirect(url_for('login'))

@appFlask.route('/anon_result/query/query_result', methods=['GET'])
def query_result():
    '''
    Function for query
    '''
    if g.user:
        if FLAG_ACCESS_CONTROL == 1 and not check_permission(a_session, session['user'],"anon"):
            flash("The Anonymization feature is not accessible by you", "danger")
            return render_template('home.html', role_name=session['role_name'],
                                       bank_balance=session['bank_balance'],
                                       user=session['user'])
        results = prepare_and_anon(int(session['k_value']))
        q_results = query_anon(results, int(session['q_value']))
        analyse_query(int(session['q_value']))
        return render_template('query_result.html', k_value=session['k_value'],
                               q_value = session['q_value'], q_results=drop_col(q_results))
    return redirect(url_for('login'))

if __name__ == "__main__":
    if SSL_FLAG == 1:
        appFlask.run(host='127.0.0.1', ssl_context=(CERT_PEM, KEY_PEM))
    else:
        appFlask.run(host='127.0.0.1')
