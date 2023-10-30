'''This Module is to do access checking'''
from sqlalchemy import text
from .init_db import AES_KEY

def check_permission(a_session, email, action):
    """
    Function to check if a user has the relavent permissions
    to execute an operation.
    """
    roleid = a_session.execute(text("""SELECT role_id FROM employee
                                    WHERE pgp_sym_decrypt(email,:AES_key)=:email"""),
                                    {"email":email,"AES_key":AES_KEY}).fetchone()
    role_id = roleid[0]
    if action == "edit":
        permission = a_session.execute(text("""SELECT pgp_sym_decrypt(manage_emp,:AES_key)
                                            FROM permissions WHERE role_id=:role_id"""),
                                            {"role_id":role_id, "AES_key":AES_KEY}).fetchone()

    elif action == "create":
        permission = a_session.execute(text("""SELECT pgp_sym_decrypt(manage_emp,:AES_key)
                                            FROM permissions WHERE role_id=:role_id"""),
                                            {"role_id":role_id, "AES_key":AES_KEY}).fetchone()

    elif action == "issue_pay":
        permission = a_session.execute(text("""SELECT pgp_sym_decrypt(issue_pay, :AES_key)
                                            FROM permissions WHERE role_id=:role_id"""),
                                            {"role_id":role_id,"AES_key":AES_KEY}).fetchone()

    elif action == "manage_invest":
        permission = a_session.execute(text("""SELECT pgp_sym_decrypt(manage_invest, :AES_key)
                                            FROM permissions WHERE role_id=:role_id"""),
                                            {"role_id":role_id,"AES_key":AES_KEY}).fetchone()

    elif action == "log":
        permission = a_session.execute(text("""SELECT pgp_sym_decrypt(view_logs, :AES_key)
                                            FROM permissions
                                            WHERE role_id=:role_id"""),
                                            {"role_id":role_id, "AES_key":AES_KEY}).fetchone()

    elif action == "approve loan":
        permission = a_session.execute(text("""SELECT pgp_sym_decrypt(manage_loans, :AES_key)
                                            FROM permissions WHERE role_id=:role_id"""),
                                            {"role_id":role_id, "AES_key":AES_KEY}).fetchone()

    elif action == "anon":
        permission = a_session.execute(text("""SELECT pgp_sym_decrypt(access_anon, :AES_key)
                                            FROM permissions
                                            WHERE role_id=:role_id"""),
                                            {"role_id":role_id, "AES_key":AES_KEY}).fetchone()

    perm = permission[0]
    if perm == "True":
        return True
    return False
