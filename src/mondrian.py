"""
main module of mondrian
"""

import time
from functools import cmp_to_key
from .utils.utility import cmp_value, value, merge_qi_value


QI_LEN = 10
GL_K = 0
RESULT = []
QI_RANGE = []
QI_DICT = []
QI_ORDER = []


class Partition:

    """
    Class for Group (or EC), which is used to keep records
    self.member: records in group
    self.low: lower point, use index to avoid negative values
    self.high: higher point, use index to avoid negative values
    self.allow: show if partition can be split on this QI
    """

    def __init__(self, data, low, high):
        """
        split_tuple = (index, low, high)
        """
        self.low = list(low)
        self.high = list(high)
        self.member = data[:]
        self.allow = [1] * QI_LEN

    def add_record(self, record):
        """
        add one record to member
        """
        self.member.append(record)

    def add_multiple_record(self, records, dim):
        """
        add multiple records (list) to partition
        """
        for record in records:
            self.add_record(record, dim)

    def __len__(self):
        """
        return number of records
        """
        return len(self.member)


def get_normalized_width(partition, index):
    """
    return Normalized width of partition
    similar to NCP
    """
    d_order = QI_ORDER[index]
    width = value(d_order[partition.high[index]]) - value(d_order[partition.low[index]])
    if width == QI_RANGE[index]:
        return 1
    return width * 1.0 / QI_RANGE[index]


def choose_dimension(partition):
    """
    choose dim with largest norm_width from all attributes.
    This function can be upgraded with other distance function.
    """
    max_width = -1
    max_dim = -1
    for dim in range(QI_LEN):
        if partition.allow[dim] == 0:
            continue
        norm_width = get_normalized_width(partition, dim)
        if norm_width > max_width:
            max_width = norm_width
            max_dim = dim
    return max_dim


def frequency_set(partition, dim):
    """
    get the frequency_set of partition on dim
    """
    frequency = {}
    for record in partition.member:
        try:
            frequency[record[dim]] += 1
        except KeyError:
            frequency[record[dim]] = 1
    return frequency


def find_median(partition, dim):
    """
    find the middle of the partition, return split_val
    """
    # use frequency set to get median
    frequency = frequency_set(partition, dim)
    split_val = ''
    next_val = ''
    value_list = list(frequency.keys())
    value_list.sort(key=cmp_to_key(cmp_value))
    total = sum(frequency.values())
    middle = total // 2
    if middle < GL_K or len(value_list) <= 1:
        try:
            return '', '', value_list[0], value_list[-1]
        except IndexError:
            return '', '', '', ''
    index = 0
    split_index = 0
    for i, qi_value in enumerate(value_list):
        index += frequency[qi_value]
        if index >= middle:
            split_val = qi_value
            split_index = i
            break
    else:
        print("Error: cannot find split_val")
    try:
        next_val = value_list[split_index + 1]
    except IndexError:
        # there is a frequency value in partition
        # which can be handle by mid_set
        # e.g.[1, 2, 3, 4, 4, 4, 4]
        next_val = split_val
    return (split_val, next_val, value_list[0], value_list[-1])


def anonymize_strict(partition):
    """
    recursively partition groups until not allowable
    """
    allow_count = sum(partition.allow)
    # only run allow_count times
    if allow_count == 0:
        RESULT.append(partition)
        return
    for _ in range(allow_count):
        # choose attrubite from domain
        dim = choose_dimension(partition)
        if dim == -1:
            print("Error: dim=-1")
        (split_val, next_val, low, high) = find_median(partition, dim)
        # Update parent low and high
        if low != '':
            partition.low[dim] = QI_DICT[dim][low]
            partition.high[dim] = QI_DICT[dim][high]
        if split_val in {'', next_val}:
            # cannot split
            partition.allow[dim] = 0
            continue
        # split the group from median
        mean = QI_DICT[dim][split_val]
        lhs_high = partition.high[:]
        rhs_low = partition.low[:]
        lhs_high[dim] = mean
        rhs_low[dim] = QI_DICT[dim][next_val]
        lhs = Partition([], partition.low, lhs_high)
        rhs = Partition([], rhs_low, partition.high)
        for record in partition.member:
            pos = QI_DICT[dim][record[dim]]
            if pos <= mean:
                # lhs = [low, mean]
                lhs.add_record(record)
            else:
                # rhs = (mean, high]
                rhs.add_record(record)
        # check is lhs and rhs satisfy k-anonymity
        if len(lhs) < GL_K or len(rhs) < GL_K:
            partition.allow[dim] = 0
            continue
        # anonymize sub-partition
        anonymize_strict(lhs)
        anonymize_strict(rhs)
        return
    RESULT.append(partition)


def init(data, k, qi_num=-1):
    """
    reset global variables
    """
    global GL_K, RESULT, QI_LEN, QI_DICT, QI_RANGE, QI_ORDER
    if qi_num <= 0:
        QI_LEN = len(data[0]) - 1
    else:
        QI_LEN = qi_num
    GL_K = k
    RESULT = []
    # static values
    QI_DICT = []
    QI_ORDER = []
    QI_RANGE = []
    att_values = []
    for i in range(QI_LEN):
        att_values.append(set())
        QI_DICT.append(dict())
    for record in data:
        for i in range(QI_LEN):
            att_values[i].add(record[i])
    for i in range(QI_LEN):
        value_list = list(att_values[i])
        value_list.sort(key=cmp_to_key(cmp_value))
        QI_RANGE.append(value(value_list[-1]) - value(value_list[0]))
        QI_ORDER.append(list(value_list))
        for index, qi_value in enumerate(value_list):
            QI_DICT[i][qi_value] = index


def mondrian(data, k, qi_num=-1):
    """
    Main function of mondrian
    """
    init(data, k, qi_num)
    result = []
    data_size = len(data)
    low = [0] * QI_LEN
    high = [(len(t) - 1) for t in QI_ORDER]
    whole_partition = Partition(data, low, high)
    # begin mondrian
    start_time = time.time()
    anonymize_strict(whole_partition)
    rtime = float(time.time() - start_time)
    # generalization result and
    # evaluation information loss
    ncp = 0.0
    risk = 0
    for partition in RESULT:
        rncp = 0.0
        for index in range(QI_LEN):
            rncp += get_normalized_width(partition, index)
        rncp *= len(partition)
        ncp += rncp
        if len(partition) <= k:
            risk += len(partition)
        for record in partition.member[:]:
            for index in range(QI_LEN):
                record[index] = merge_qi_value(QI_ORDER[index][partition.low[index]],
                                QI_ORDER[index][partition.high[index]])
            result.append(record)

    ncp /= QI_LEN
    ncp /= data_size
    ncp *= 100

    return (result, (ncp, rtime, risk))
