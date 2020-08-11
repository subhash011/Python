import numpy as np
import pandas as pd
import seaborn as sns
import os
import requests
import shutil
import random
import json
import pprint
import re
import statistics
from collections import defaultdict as dd
from sklearn import preprocessing
import pickle
import time
from ast import literal_eval
from constants import *


# extract network features
def get_network_features(data):
    dns_req_types = ["A", "AAAA", "MX", "SRV", "TXT", "PTR"]
    file_features = dd(lambda: 0)
    network = data["network"]
    file_features["udp"] = len(network["udp"])
    file_features["ips"] = len(set([ip["src"] for ip in network["udp"]]))
    file_features["udp_dest_ports"] = len(set([ip["dst"] for ip in network["udp"]]))
    file_features["irc"] = len(network["irc"])
    file_features["http"] = len(network["http"])
    file_features["smtp"] = len(network["smtp"])
    file_features["tcp"] = len(network["tcp"])
    file_features["icmp"] = len(network["icmp"])
    file_features["hosts"] = len(network["hosts"])
    file_features["dns"] = len(network["dns"])
    for x in dns_req_types:
        file_features[x] = 0
    for x in [1, 2, 3, 4]:
        key = "dom_freq_" + str(x)
        file_features[key] = 0
    for x in network["dns"]:
        file_features[x["type"]] += 1
    file_features["domains"] = len(network["domains"])
    for x in network["domains"]:
        domain_levels = x["domain"].split(".")
        if len(domain_levels) >= 5:
            file_features["dom_freq_4"] += 1
        elif len(domain_levels) >= 2:
            key = "dom_freq_" + str(len(domain_levels) - 1)
            file_features[key] += 1
    return file_features


def get_file_system_features(data):
    file_features = dd(lambda: 0)
    for ext in file_exts:
        file_features["files_modified_" + ext] = 0
    for ext in file_exts:
        file_features["files_opened_" + ext] = 0
    for ext in file_exts:
        file_features["files_created_" + ext] = 0
    for ext in file_exts:
        file_features["files_deleted_" + ext] = 0
    behaviour = data["behavior"]
    generics = behaviour["generic"]
    for generic in generics:
        summary = generic["summary"]
        parameters = summary.keys()
        for x in file_features_needed:
            file_features[x] = 0
        if "file_recreated" in parameters:
            file_features["files_modified"] = len(summary["file_recreated"])
            for file in summary["file_recreated"]:
                ext_split = file.split(".")
                ext = ext_split[len(ext_split) - 1]
                if ext in file_exts:
                    file_features["files_modified_" + ext] += 1
        if "file_opened" in parameters:
            file_features["files_opened"] = len(summary["file_opened"])
            for file in summary["file_opened"]:
                ext_split = file.split(".")
                ext = ext_split[len(ext_split) - 1]
                if ext in file_exts:
                    file_features["files_opened_" + ext] += 1
        if "file_copied" in parameters:
            file_features["files_copied"] = len(summary["file_copied"])
        if "file_failed" in parameters:
            file_features["files_failed"] = len(summary["file_failed"])
        if "file_created" in parameters:
            file_features["files_created"] = len(summary["file_created"])
            for file in summary["file_created"]:
                ext_split = file.split(".")
                ext = ext_split[len(ext_split) - 1]
                if ext in file_exts:
                    file_features["files_created_" + ext] += 1
        if "file_written" in parameters:
            file_features["files_written"] = len(summary["file_written"])
        if "file_exists" in parameters:
            file_features["files_exists"] = len(summary["file_exists"])
        if "file_deleted" in parameters:
            file_features["files_deleted"] = len(summary["file_deleted"])
            for file in summary["file_deleted"]:
                ext_split = file.split(".")
                ext = ext_split[len(ext_split) - 1]
                if ext in file_exts:
                    file_features["files_deleted_" + ext] += 1
        if "dll_loaded" in parameters:
            file_features["dll_loaded"] = len(summary["dll_loaded"])
        if "regkey_opened" in parameters:
            file_features["regkey_opened"] = len(summary["regkey_opened"])
        if "regkey_read" in parameters:
            file_features["regkey_read"] = len(summary["regkey_read"])
        if "regkey_written" in parameters:
            file_features["regkey_written"] = len(summary["regkey_written"])
        if "regkey_deleted" in parameters:
            file_features["regkey_deleted"] = len(summary["regkey_deleted"])
        if "directory_enumerated" in parameters:
            file_features["directory_enumerated"] = len(summary["directory_enumerated"])
        if "directory_removed" in parameters:
            file_features["directory_removed"] = len(summary["directory_removed"])
        if "directory_created" in parameters:
            file_features["directory_created"] = len(summary["directory_created"])
    return file_features


def get_processes_features(data):
    file_features = dd(lambda: 0)
    for x in call_categories:
        file_features["cat_count_" + x] = 0
        file_features["cat_per_" + x] = 0
    for x in api_calls:
        file_features[x] = 0
    processes = data["behavior"]["processes"]
    for process in processes:
        if len(process["calls"]) != 0:
            totcalls = 0
            for call in process["calls"]:
                if call["category"] in call_categories:
                    file_features["cat_count_" + call["category"]] += 1
                if call["api"] in api_calls:
                    file_features[call["api"]] += 1
                totcalls += 1
            for x in call_categories:
                file_features["cat_per_" + x] = file_features["cat_count_" + x] / totcalls
    return file_features


def get_misc_features(data):
    file_features = dd(lambda: 0)
    signatures = data["signatures"]
    severity = []
    for x in cuckoo_signatures:
        file_features[x] = 0
    for signature in signatures:
        severity.append(signature['severity'])
        name = signature["name"]
        if name in cuckoo_signatures:
            file_features[name] += 1
    if len(severity) == 0:
        severity = [0]
    severity = statistics.mean(severity)
    file_features["severity"] = severity
    virus_detected_count = 0
    total_scans = 0
    try:
        virus_scans = data['virustotal']['scans']
        total_scans = len(virus_scans.keys())
        for scanner in virus_scans.keys():
            if virus_scans[scanner]["detected"] == True:
                virus_detected_count += 1
    except:
        pass
    if total_scans == 0:
        total_scans = 1
    file_features["scans_perc"] = (virus_detected_count / total_scans) * 100
    generic_behaviour = data["behavior"]["generic"]
    dll_loaded = 0
    for behaviour in generic_behaviour:
        try:
            dll_loaded += len(behaviour["summary"]["dll_loaded"])
        except:
            pass
    file_features["dll_loaded"] = dll_loaded
    processes = data["behavior"]["processes"]
    file_features["processes"] = len(processes)
    return file_features


def get_features(path):
    features_required = []
    for file in os.listdir(path):
        file_features = dd()
        with open(os.path.join(path, file), "r") as f:
            data = json.load(f)
            filesystem_features = get_file_system_features(data)
            network_features = get_network_features(data)
            process_features = get_processes_features(data)
            misc_features = get_misc_features(data)
            file_features.update(filesystem_features)
            file_features.update(network_features)
            file_features.update(process_features)
            file_features.update(misc_features)
            features_required.append(file_features)
    return features_required


def get_features_of_file(folder, file):
    file_features = dd()
    with open(os.path.join(folder, file), "r") as f:
        data = json.load(f)
        filesystem_features = get_file_system_features(data)
        network_features = get_network_features(data)
        process_features = get_processes_features(data)
        misc_features = get_misc_features(data)
        file_features.update(filesystem_features)
        file_features.update(network_features)
        file_features.update(process_features)
        file_features.update(misc_features)
    return file_features


def get_dll_and_function(line):
    dll_func = line.split()
    dll_func = dll_func[0].split(".")
    dll = ".".join(dll_func[:2])
    function = dll_func[len(dll_func) - 1]
    return dll.lower(), function


def get_features_static(lines):
    file_features = dd(lambda: 0)
    dlls = set()
    functions = set()
    dll_func_regex = re.compile(r'Hint\[\d*\]')
    for x in function_calls:
        file_features[x] = 0
    for x in dlls_required:
        file_features[x] = 0
    for x in meta_data_features:
        file_features[x] = 0
    for line in lines:
        line = line.replace(":", "")
        params = line.split()
        for x in meta_data_features:
            if x in line:
                try:
                    value = literal_eval(params[params.index(x) + 1])
                    file_features[x] = value
                except:
                    pass
            elif x == "CompileTimeIndicator":
                if "TimeDateStamp" in line:
                    now_time = int(time.time())
                    value = literal_eval(params[params.index("TimeDateStamp") + 1])
                    if value > now_time:
                        file_features[x] = 1
                    else:
                        file_features[x] = 0
            if dll_func_regex.search((line)):
                dll, function = get_dll_and_function(line)
                dlls.add(dll)
                functions.add(function)
                if dll in dlls_required:
                    file_features[dll] += 1
                if function in function_calls:
                    file_features[function] += 1
        file_features["NumberOfDLLs"] = len(dlls)
        file_features["NumberOfFunctions"] = len(functions)
    return file_features


def get_static_file_features(path, folder):
    files = os.listdir(os.path.join(path, folder))
    file = files[1]
    path = os.path.join(path, folder)
    with open(os.path.join(path, files[0])) as f:
        lines = f.readlines()
        for line in lines:
            if "---DOS_HEADER---" in line:
                file = files[0]
                break
    with open(os.path.join(path, file)) as f:
        lines = f.readlines()
        features = get_features_static(lines)
        return features
