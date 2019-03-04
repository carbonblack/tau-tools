      ________      _____                              __   ___
     / ___/ _ )____/ ___/__  __ _  __ _  ___ ____  ___/ /  / _ \
    / /__/ _  /___/ /__/ _ \/  ' \/  ' \/ _ `/ _ \/ _  /  / , _/
    \___/____/    \___/\___/_/_/_/_/_/_/\_,_/_//_/\_,_/__/_/|_|
                                                     /___/

### Carbon Black Response - Mass Command Line Data Extractor

Multithreaded large-scale Carbon Black Response Command Line Data Extraction

## Installation

This script is meant to run with Python version 2, however it can work with Python v3 with some simple modifications.

First things first, install the requirements:

    $ pip install -r requirements.txt

Modify config.py to include your Carbon Black Response domain and associated API key.

This setting allows for multiple configurations - just make sure the one you would like to use is placed within the 'active' section.

## Execution

Run the script with -h or --help to view the help options:

    usage: cb-command_r.py [-h] [-q QUERY] [-t THREADS] [-r ROWS] [-s START] [-f FILENAME]
      optional arguments:
       -h, --help            show this help message and exit
       -q QUERY, --query QUERY
                             Carbon Black Response Query
                             Default: (process_name:cmd.exe)
       -t THREADS, --threads THREADS
                             Number of simultaneous threads
                             Default: 25
       -r ROWS, --rows ROWS  
                             Rows per thread (USE MULTIPLES OF 10!)
                             Default: 1000
       -s START, --start START
                             Select the starting row
                             Default: 0
       -f FILENAME, --filename FILENAME
                             Output results
                             Default: commands.txt

Running the script with no options will utilize the defaults as described above, however these can be customized to fit with the number of queries you're pulling. Below is more information on each flag:

##### -q | --query: 

Defines the Carbon Black Response formatted query you'd like to search to associated command line parameters across. This will work with any process but some recommended ones:

    process_name:cmd.exe (default)
    process_name:powershell.exe
    process_name:bash
    process_name:sh

##### -t | --threads:

Defines the number of simultaneous threads you would like to run. You should aim to keep this below 50 to avoid running into issues with storing large amounts of data in memory.

    Default value: 25

If you choose to run this script with 1 thread, this will make only a single API call for the command line arguments.

##### -r | --rows:

Defines the number of rows to pull back per thread. These must be defined in increments of 10, due to how multithreading is configured in this script.

The absolute maximum you can query from a single thread is 10,000

Available options:

    1, 10, 100, 1000, 10000
    Default value: 1000

##### -s | --start:

Defines the starting row the script will begin searching over. Default is 1, but can be adjusted to start from wherever you left off after a prior request

    Default value: 1

##### -f | --filename:

Defines where you would like to save the output of the script.

    Default value: commands.txt

### Author

gfoss[at]carbonblack.com

March, 2019

### Example

Help Menu:

![cb-command_r_1](https://user-images.githubusercontent.com/727732/53764619-07939700-3e8b-11e9-8fc4-b8c5dae7cd07.png)

Query Execution:

![cb-command_r_2](https://user-images.githubusercontent.com/727732/53764627-0bbfb480-3e8b-11e9-90bd-b620ca452b91.png)
