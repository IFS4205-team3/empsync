'''Module to update a database query'''
import re
from passlib.hash import sha256_crypt
from sqlalchemy import text
from flask import flash, request
from .init_db import AES_KEY

def update_pass(a_session, user_id, new_password):
    """
    Function to update password of employee
    """
    new_password = sha256_crypt.hash(new_password)
    a_session.execute(text("""UPDATE EMPLOYEE SET acc_password
            =pgp_sym_encrypt(:new_pass,:AES_key) WHERE pgp_sym_decrypt(email,:AES_key) 
            =:email"""),{"new_pass":new_password,"email": user_id, "AES_key":AES_KEY})
    a_session.commit()


def perform_edit(information, session, a_session, field):
    """
    Function to update employee database during edit
    """
    if len(information["first_name"].strip()) != 0:
        #update first name
        a_session.execute(text(
            """UPDATE employee SET first_name=pgp_sym_encrypt(:first_name,:AES_key)
              WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
            {"first_name":information["first_name"],
             "email":information["email"], "AES_key":AES_KEY})
        a_session.commit()

        field["statement"] += "first name, "
        field["count"] += 1

    if len(information["last_name"].strip()) != 0:
        #update last name
        a_session.execute(text(
            """UPDATE employee SET last_name=pgp_sym_encrypt(:last_name,:AES_key)
            WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
            {"last_name":information["last_name"], "email":information["email"], "AES_key":AES_KEY})
        a_session.commit()

        field["statement"] += "last name, "
        field["count"] += 1

    if len(information["date_of_birth"].strip()) != 0:
        #update date_of_birth
        a_session.execute(text(
            """UPDATE employee SET date_of_birth=pgp_sym_encrypt(:date_of_birth,:AES_key)
            WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
            {"date_of_birth":information["date_of_birth"], "email":information["email"],
             "AES_key":AES_KEY})
        a_session.commit()

        field["statement"] += "date of birth, "
        field["count"] += 1

    if len(information["phone_number"].strip()) != 0:
        a_session.execute(text(
            """UPDATE employee SET phone_number=pgp_sym_encrypt(:phone_number,:AES_key)
            WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
            {"phone_number":information["phone_number"], "email":information["email"],
             "AES_key":AES_KEY})
        a_session.commit()

        field["statement"] += "phone number, "
        field["count"] += 1

    if len(information["role_id"].strip()) != 0 and information["role_id"] != "NA":
        a_session.execute(text(
            """UPDATE employee SET role_id=:role_id WHERE
            pgp_sym_decrypt(email,:AES_key)=:email"""),
            {"role_id":information["role_id"], "email":information["email"],
             "AES_key":AES_KEY})
        a_session.commit()

        log_action(a_session, session['user'], "edit role_id of emp_id: "
                   + information["emp_id"] + " to role id: " + information["role_id"])

        field["statement"] += "role, "
        field["count"] += 1

    if len(information["salary"].strip()) != 0 :
        a_session.execute(text(
            """UPDATE employee SET salary=pgp_sym_encrypt(:salary,:AES_key) WHERE
            pgp_sym_decrypt(email, :AES_key)=:email"""),
            {"salary":information["salary"], "email":information["email"], "AES_key":AES_KEY})
        a_session.commit()

        field["statement"] += "salary, "
        field["count"] += 1

    if len(information["bank_account"].strip()) != 0:
        a_session.execute(text(
            """UPDATE employee SET bank_account=pgp_sym_encrypt(:bank_account,:AES_key) WHERE
            pgp_sym_decrypt(email, :AES_key)=:email"""),
            {"bank_account":information["bank_account"],
             "email":information["email"], "AES_key":AES_KEY})
        a_session.commit()

        field["statement"] += "bank account, "
        field["count"] += 1

    field["statement"] = field["statement"][:-2]
    if field["count"] > 1:
        temp = field["statement"].rsplit(', ', 1)
        field["statement"] = ' and '.join(temp)
    log_action(a_session, session['user'], "updated the following field(s): " + field["statement"] +
                   " for emp_id: " + information["emp_id"])
    flash("Updated the following field(s): " + field["statement"], "success")

def is_valid_first_name(information, field):
    """
    Function to check whether first name provided is valid
    """
    if len(information["first_name"].strip()) != 0:
        if re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\|`/\'"=-]', information["first_name"]):
            flash("First name must not contain symbols", "danger")
            return False
        field["count"] += 1
    return True

def is_valid_last_name(information, field):
    """
    Function to check whether last name provided is valid
    """
    if len(information["last_name"].strip()) != 0:
        if re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\|`/\'"=-]', information["last_name"]):
            flash("Last name must not contain symbols", "danger")
            return False
        field["count"] += 1
    return True

def is_valid_date_of_birth(information, field):
    """
    Function to check whether date of birth provided is valid
    """
    if len(information["date_of_birth"].strip()) != 0:
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', information["date_of_birth"]):
            flash("Date of birth must be of format yyyy-mm-dd", "danger")
            return False
        field["count"] += 1
    return True

def is_valid_phone_number(information, field):
    """
    Function to check whether phone number provided is valid
    """
    if len(information["phone_number"].strip()) != 0:
        if not information["phone_number"].isdigit():
            flash("Phone number must be digits", "danger")
            return False
        field["count"] += 1
    return True

def is_valid_role_id(information, a_session, field):
    """
    Function to check whether role id provided is valid
    """
    if len(information["role_id"].strip()) != 0:
        if information["role_id"] != "NA":
            max_role_id_var = a_session.execute(text(
                """SELECT MAX(role_id) FROM permissions""")).fetchone()
            a_session.commit()
            print(max_role_id_var[0])
            max_role_id = max_role_id_var[0]
            if information["role_id"].isdigit():
                if int(information["role_id"]) <= max_role_id:
                    field["count"] += 1
                else:
                    flash("Role id must be a number that already exist", "danger")
                    return False
            else:
                flash("Role id must be a number that already exist", "danger")
                return False
    return True

def is_valid_salary(information, field):
    """
    Function to check whether salary provided is valid
    """
    if len(information["salary"].strip()) != 0:
        if not (information["salary"].isdigit() and float(information["salary"]) >= 0):
            flash("Salary must be non-negative numbers", "danger")
            return False
        field["count"] += 1
    return True

def is_valid_bank_account(information, field):
    """
    Function to check whether bank account provided is valid
    """
    if len(information["bank_account"].strip()) != 0:
        if not information["bank_account"].isdigit():
            flash("Bank account must be digits", "danger")
            return False
        field["count"] += 1
    return True

def edit_employee_details(session, a_session):
    """
    Function to check and update employee database during edit
    """
    information = {}
    information["email"] = request.form.get("email")
    usernamedata = a_session.execute(text("""SELECT pgp_sym_decrypt(email, :AES_key) FROM
            employee WHERE pgp_sym_decrypt(email,:AES_key)=:email"""),
            {"email":information["email"],"AES_key":AES_KEY}).fetchone()
    if usernamedata is None:
        flash("The email provided is not found in the database", "danger")
        return
    # get emp_id of acc to be updated
    emp_id_var = a_session.execute(text("""SELECT emp_id FROM
            employee WHERE pgp_sym_decrypt(email,:AES_key)=:email"""),
            {"email":information["email"], "AES_key":AES_KEY}).fetchone()
    information["emp_id"] = str(emp_id_var[0])

    field = {}
    field["count"] = 0
    field["statement"] = ""

    information["first_name"] = request.form.get("first_name")
    information["last_name"] = request.form.get("last_name")
    information["date_of_birth"] = request.form.get("dob")
    information["phone_number"] = request.form.get("phone_number")
    information["role_id"] = request.form.get("role_id")
    information["salary"] = request.form.get("salary")
    information["bank_account"] = request.form.get("bank_account")

    # check inputs, nothing will be updated if any input is invalid
    if not (is_valid_first_name(information, field) and
            is_valid_last_name(information, field) and
            is_valid_date_of_birth(information, field) and
            is_valid_phone_number(information, field) and
            is_valid_role_id(information, a_session, field) and
            is_valid_salary(information, field) and
            is_valid_bank_account(information, field)):
        return

    if field["count"] == 0:
        flash(
    "No fields are updated, please provide a valid input for at least one of the optional fields",
    "danger")
        return
    field["statement"] = ""
    field["count"] = 0
    # all input passed the checks, update the database with the input provided
    perform_edit(information, session, a_session, field)

def log_action(a_session, email, exec_operation):
    """
    Function to log all actions performed.
    """
    emp_id_var = a_session.execute(text(
        """SELECT emp_id FROM employee WHERE pgp_sym_decrypt(email, :AES_key)=:email"""),
        {"email":email, "AES_key":AES_KEY}).fetchone()
    for e_id in emp_id_var:
        emp_id = str(e_id)
        a_session.execute(text("""INSERT INTO log_history (emp_id, exec_operation)
                    VALUES (:emp_id, pgp_sym_encrypt(:exec_operation, :AES_key))"""),
                    {"emp_id":emp_id, "exec_operation":exec_operation, "AES_key":AES_KEY})
    a_session.commit()
