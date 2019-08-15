#!/usr/env python

# CB-Command_R
# Carbon Black Response - Mass Command Line Data Extractor
# gfoss[at]carbonblack.com
# March, 2019

import sys, time, argparse, requests, json, threading, thread
from config import active

global_lock = threading.Lock()
file_contents = []

def parse_all_things():
  parser = argparse.ArgumentParser(description = 'Multithreaded large-scale Carbon Black Response Command Line Data Extraction')
  parser.add_argument('-q', '--query', help = 'Carbon Black Response Query - Default: (process_name:cmd.exe)', default='process_name:cmd.exe', dest='query')
  parser.add_argument('-t', '--threads', help = 'Number of simultaneous threads - Default: 25', default='25', dest='threads')
  parser.add_argument('-r', '--rows', help = 'Rows per thread (USE MULTIPLES OF 10!) - Default: 1000', default='1000', dest='rows')
  parser.add_argument('-s', '--start', help = 'Select the starting row - Default: 0', default='0', dest='start')
  parser.add_argument('-f', '--filename', help = 'Output results - Default: commands.txt', default='commands.txt', dest='filename', )
    #
    # usage: cb-command_r.py [-h] [-q QUERY] [-t THREADS] [-r ROWS] [-s START] [-f FILENAME]
    #
    # Multithreaded large-scale Carbon Black Response Commandline Data Extraction
    #
    # optional arguments:
    #  -h, --help            show this help message and exit
    #  -q QUERY, --query QUERY
    #                        Carbon Black Response Query
    #                        Default: (process_name:cmd.exe)
    #  -t THREADS, --threads THREADS
    #                        Number of simultaneous threads
    #                        Default: 25
    #  -r ROWS, --rows ROWS  
    #                        Rows per thread (USE MULTIPLES OF 10!)
    #                        Default: 1000
    #  -s START, --start START
    #                        Select the starting row
    #                        Default: 0
    #  -f FILENAME, --filename FILENAME
    #                        Output results
    #                        Default: commands.txt
    #
  return parser

def extractor(parser, args, start_count):
  url = active['url']
  api_key = active['key']
  
  query = args.query
  querystring = {"q":args.query,"rows":args.rows,"start":start_count}

  payload = ""
  headers = { 'X-Auth-Token': api_key }

  # If you receieve SSL certificate errors, add ", verify=False" to the below request
  response = requests.request("GET", url, data=payload, headers=headers, params=querystring)
  data = json.loads(response.content)

  if int(args.threads) > 1:

    while global_lock.locked():
      continue

    global_lock.acquire()
    rows = int(args.rows)
    for num in range(rows):
      datas = (data['results'][num]['cmdline']).encode('utf8')
      file_contents.append(datas)
    global_lock.release()

  else:

    orig_stdout = sys.stdout
    f = open(args.filename, 'a')
    sys.stdout = f
    rows = int(args.rows)
    for num in range(rows):
      print (data['results'][num]['cmdline']).encode('utf8')
    sys.stdout = orig_stdout
    f.close()

def main():

  print '''
      ________      _____                              __   ___ 
     / ___/ _ )____/ ___/__  __ _  __ _  ___ ____  ___/ /  / _ \\
    / /__/ _  /___/ /__/ _ \\/  \' \\/  \' \\/ _ `/ _ \\/ _  /  / , _/
    \\___/____/    \\___/\\___/_/_/_/_/_/_/\\_,_/_//_/\\_,_/__/_/|_| 
                                                     /___/      
  '''

  parser = parse_all_things()
  args = parser.parse_args()

  thread_count = args.threads
  start_count = args.start
  rows = args.rows

  if int(thread_count) > 1:
    
    print 'Extracting the last ' + thread_count + str(rows)[1:] + ' commands related to: ' + args.query
    print 'Running with ' + thread_count + ' threads!'
    print ''
    thread_count = int(thread_count)

    threads = []
    for num in range(thread_count):
      iteration = str(rows)[1:]
      start_count = str(num) + iteration
      print 'Pulling ' + start_count + ' rows of command line data'
      t = threading.Thread(target=extractor, args=(parser,args,start_count,))
      threads.append(t)
      t.start()
    [thread.join() for thread in threads]

    with open(args.filename, 'a+') as file:
      file.write('\n'.join(file_contents))
      file.close()

    print ''
    print 'Writing output to ' + args.filename
    print ''

  else:
    print "Making a single API request for " + rows + " records..."
    extractor(parser, args, start_count)

    print ''
    print 'Writing output to ' + args.filename
    print ''
    
if __name__ == "__main__":
  main()
