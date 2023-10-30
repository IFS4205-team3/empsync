"""
run mondrian with given parameters
"""

import copy
import matplotlib.pyplot as plt
from .mondrian import mondrian

INTUITIVE_ORDER = None

def get_result_one(data, k):
    """
    run mondrian for one time
    """
    data_back = copy.deepcopy(data)
    result = mondrian(data, k)
    data = copy.deepcopy(data_back)
    return result[0]

def run_anon(data, k):
    '''
    Driver to run anonymization once
    '''
    data
    return get_result_one(data, k)

def plot_diff_k(data):
    '''
    Function to plot graph against different K 
    '''
    k_array = [2, 5, 10, 15, 20, 30]
    ncp_list = []
    dp_list = []
    for k_value in k_array:
        data_back = copy.deepcopy(data)
        _, eval_result = mondrian(data, k_value)
        data = copy.deepcopy(data_back)
        ncp_list.append(eval_result[0])
        dp_list.append(eval_result[2])

    plt.clf()
    plt.figure(1)
    plt.plot(k_array, ncp_list, marker='o')
    plt.xlabel('k')
    plt.ylim(0, 100)
    plt.ylabel('Normalized Certainty Penalty (NCP)%')
    plt.title('Normalized Certainty Penalty (NCP) vs k')
    plt.savefig('static/ncp_output.jpg')

    plt.clf()
    plt.figure(2)
    plt.plot(k_array, dp_list, marker='o')
    plt.xlabel('k')
    plt.ylabel('Re-Identification Risk (Weights)')
    plt.title('K-Anon Violation vs k')
    plt.savefig('static/dp_output.jpg')

def is_within_range(input_str, x):
    '''
    Function to count for query age
    '''
    try:
        lower, upper = map(int, input_str.split('~'))
        return lower <= x <= upper
    except (ValueError, TypeError):
        # Handle invalid input or conversion errors
        return False

def plot_query_k(data, ori_count, query_value):
    '''
    Function to plot graph for query analysis
    '''
    k_array = [2, 5, 10, 15, 20, 30]
    q_array = []
    if ori_count == 0:
        ori_count = 1
    for k_value in k_array:
        data_back = copy.deepcopy(data)
        result = mondrian(data, k_value)
        data = copy.deepcopy(data_back)
        query_count = 0
        for row in result[0]:
            if is_within_range(row[0], query_value):
                query_count += 1
        if query_count == 0:
            query_count = 1
        q_array.append(query_count/ori_count)
    plt.clf()
    plt.figure(3)
    plt.plot(k_array, q_array, marker='o')
    plt.xlabel('k')
    plt.ylabel('Query Ratio %')
    plt.title('Query Ratio vs k')
    plt.savefig('static/query_ratio_output.jpg')
