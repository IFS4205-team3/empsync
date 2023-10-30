'''
Module to drive anonymization
'''

from datetime import datetime
import math
from sqlalchemy import text
from .anonymizer import run_anon, plot_diff_k, plot_query_k
from .init_db import a_session, AES_KEY


def generalise_salary(salary):
    '''
    Function to generalise salary
    '''
    if salary <= 5000:
        return "0~5000"
    if salary <= 10000:
        return "5001~10000"
    if salary <= 15000:
        return "10001~15000"
    if salary <= 20000:
        return "15001~20000"
    if salary <= 25000:
        return "20001~25000"
    return "Above 25000"

def calculate_age(birthdate):
    '''
    Function to calculate age based on DOB
    '''
    birthdate = datetime.strptime(birthdate, "%Y-%m-%d")
    today = datetime.now()
    age = today.year - birthdate.year - ((today.month, today.day) < (birthdate.month,
                                                                    birthdate.day))

    return age

def round_value_up(value):
    '''
    Function to round values
    '''
    if value == 0:
        return 0
    return math.ceil(value / 500) * 500

def prepare_and_anon(k):
    '''
    Function to anonymize dataset
    '''
    #columns = ['email', 'first_name', 'last_name', 'age', 'salary', 'bank_balance',
    # 'total_loan', 'total_invest']
    curr_user=a_session.execute(text("""SELECT emp_id, pgp_sym_decrypt(email, :AES_key) as email,
                                    pgp_sym_decrypt(first_name,:AES_key) as first_name,
                                    pgp_sym_decrypt(last_name,:AES_key) as last_name,
                                    pgp_sym_decrypt(date_of_birth,:AES_key) as dob,
                                    pgp_sym_decrypt(salary,:AES_key) as salary,
                                    pgp_sym_decrypt(bank_balance,:AES_key) as bank_balance,
                                    pgp_sym_decrypt(total_invest,:AES_key) as total_invest,
                                    pgp_sym_decrypt(total_loan,:AES_key) as total_loan FROM employee
                                            """),{"AES_key":AES_KEY}).fetchall()

    data = []
    for user in curr_user:
        new_row = [calculate_age(user.dob), round_value_up(float(user.bank_balance)),
                round_value_up(float(user.total_loan)), round_value_up(float(user.total_invest)),
                generalise_salary(round_value_up(int(user.salary)))]
        data.append(new_row)

    return run_anon(data, k)

def plot_k():
    '''
    Function to plot value against k
    '''
    curr_user=a_session.execute(text("""SELECT emp_id, pgp_sym_decrypt(email, :AES_key) as email,
                                    pgp_sym_decrypt(first_name,:AES_key) as first_name,
                                    pgp_sym_decrypt(last_name,:AES_key) as last_name,
                                    pgp_sym_decrypt(date_of_birth,:AES_key) as dob,
                                    pgp_sym_decrypt(salary,:AES_key) as salary,
                                    pgp_sym_decrypt(bank_balance,:AES_key) as bank_balance,
                                    pgp_sym_decrypt(total_invest,:AES_key) as total_invest,
                                    pgp_sym_decrypt(total_loan,:AES_key) as total_loan FROM employee
                                            """),{"AES_key":AES_KEY}).fetchall()

    data = []
    for user in curr_user:
        new_row = [calculate_age(user.dob), round_value_up(float(user.bank_balance)),
                round_value_up(float(user.total_loan)), round_value_up(float(user.total_invest)),
                generalise_salary(round_value_up(int(user.salary)))]
        data.append(new_row)

    plot_diff_k(data)

def is_within_range(input_str, x):
    '''
    Function to check if age is within range
    '''
    try:
        lower, upper = map(int, input_str.split('~'))
        return lower <= x <= upper
    except (ValueError, TypeError):
        # Handle invalid input or conversion errors
        return False

def query_anon(results, query_value):
    '''
    Function to query anonymized data set
    '''
    query_results = []
    for result in results:
        if is_within_range(result[0], query_value):
            query_results.append(result)
    return query_results

def analyse_query(q_value):
    '''
    Function to analyse query dataset
    '''
    ori_count = 0
    curr_user=a_session.execute(text("""SELECT emp_id, pgp_sym_decrypt(email, :AES_key) as email,
                                    pgp_sym_decrypt(first_name,:AES_key) as first_name,
                                    pgp_sym_decrypt(last_name,:AES_key) as last_name,
                                    pgp_sym_decrypt(date_of_birth,:AES_key) as dob,
                                    pgp_sym_decrypt(salary,:AES_key) as salary, 
                                    pgp_sym_decrypt(bank_balance,:AES_key) as bank_balance,
                                    pgp_sym_decrypt(total_invest,:AES_key) as total_invest,
                                    pgp_sym_decrypt(total_loan,:AES_key) as total_loan FROM employee
                                            """),{"AES_key":AES_KEY}).fetchall()

    data = []
    for user in curr_user:
        new_row = [calculate_age(user.dob), round_value_up(float(user.bank_balance)),
                round_value_up(float(user.total_loan)),
                round_value_up(float(user.total_invest)),
                generalise_salary(round_value_up(int(user.salary)))]
        data.append(new_row)

    for row in data:
        if row[0] == int(q_value):
            ori_count += 1

    plot_query_k(data, ori_count, q_value)

def drop_col(results):
    '''
    Function to drop column
    '''
    new_result = []
    for row in results:
        new_result.append(row[0:4])
    return new_result
