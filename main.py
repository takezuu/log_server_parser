import re
import json
import argparse
import uuid


def search_ip(line, ip_results):
    ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
    ip = ip.group()
    if ip not in ip_results:
        ip_results[ip] = 1
    else:
        ip_results[ip] += 1


def search_requests(line, requests_results):
    request = re.search(r"(POST|GET|PUT|DELETE|HEAD|CONNECT|OPTIONS|TRACE)", line)
    request = request.group()
    if request not in requests_results:
        requests_results[request] = 1
    else:
        requests_results[request] += 1


def main_func(ip_results, requests_results, file, path=''):
    with open(path+file, 'r') as file:
        lines = 0
        max_time = 0
        long_requests_dict = {}
        for line in file:
            search_ip(line, ip_results)
            lines += 1
            search_requests(line, requests_results)

            splited_line = (line.split())
            time = int(splited_line[len(splited_line) - 1])

            if time >= max_time and len(long_requests_dict) < 3:
                long_requests_dict[line] = time
                sorted_tuples = sorted(long_requests_dict.items(), key=lambda item: item[1])
                long_requests_dict = {k: v for k, v in sorted_tuples}
                max_time = time
            elif time >= max_time and len(long_requests_dict) == 3:
                long_requests_dict[line] = time
                sorted_tuples = sorted(long_requests_dict.items(), key=lambda item: item[1])
                long_requests_dict = {k: v for k, v in sorted_tuples}
                long_requests_dict.pop(list(long_requests_dict)[0])
                max_time = time
    return lines, long_requests_dict


def top_ip(ip_result):
    sorted_tuples = sorted(ip_result.items(), key=lambda item: item[1])
    sorted_ip = {k: v for k, v in sorted_tuples}
    sorted_ip = list(sorted_ip)
    max_ip = list(i for i in sorted_ip[:-4:-1])
    return max_ip


def info_long_requests(long_requests_dict):
    long_requests = []
    for line in long_requests_dict:
        ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
        ip = ip.group()
        date = re.search(r"\[(.*?)\]", line)
        date = date.group()
        request = re.search(r"(POST|GET|PUT|DELETE|HEAD|CONNECT|OPTIONS|TRACE)", line)
        request = request.group()
        url = re.search(r"http[s]?..(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", line)
        if url:
            url = url.group()
        else:
            url = "url отсутствует"
        splited_line = (line.split())
        time = int(splited_line[len(splited_line) - 1])
        long_request = (ip + ' ' + date + ' ' + request + ' ' + ' ' + url + ' ' + str(time))
        long_requests.append(long_request)
    return long_requests


def json_data(all_requests, requests_results, top_ips, long_requests):
    data = {'Колличество запросов': all_requests,
            'Колличество запросов по HTTP-методам': requests_results,
            'Топ 3 IP адресов, с которых сделаны запросы': top_ips,
            'Топ 3 долгих запроса': long_requests
            }
    file_name = uuid.uuid1()
    with open(str(file_name)+'_log_results.txt', 'w') as outfile:
        json.dump(data, outfile, ensure_ascii=False, indent=4)

    print('Колличество запросов:', data['Колличество запросов'])
    print('Колличество запросов по HTTP-методам:', data['Колличество запросов по HTTP-методам'])
    print('Топ 3 IP адресов, с которых сделаны запросы:', data['Топ 3 IP адресов, с которых сделаны запросы'])
    print('Топ 3 долгих запроса:\n', data['Топ 3 долгих запроса'][0], '\n', data['Топ 3 долгих запроса'][1], '\n',
          data['Топ 3 долгих запроса'][2], '\n')

    all_requests = 0
    requests_results = {}
    ip_results = {}
    top_ips = []
    long_requests = []


parser = argparse.ArgumentParser(description='Process log')
parser.add_argument('-f', dest='file', nargs='+', action='store', help='File name', required=True)
parser.add_argument('-d', dest='directory', type=str, action='store', help='File\'s directory')
args = parser.parse_args()
for file in args.file:
    path = args.directory
    requests_results = {}
    ip_results = {}
    all_requests, long_requests_dict = main_func(ip_results, requests_results, file, path)
    top_ips = (top_ip(ip_results))
    long_requests = info_long_requests(long_requests_dict)
    json_data(all_requests, requests_results, top_ips, long_requests)
