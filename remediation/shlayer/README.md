# OSX Shlayer Cleanup Script

#### Blog: [TBD]()

#### Instructions

There are two ways to run this script. Interactively and Automatically.

First things first, ensure the script is executable:

    $ chmod +x ./shlayer-cleanup.sh

##### Interactive Execution

Allows you to step through the execution and review all files before making a decision on removing them.

    $ ./shlayer-cleanup.sh

##### Automatic Execution

Runs the script and automatically deletes any detected Shlayer malicious files.

    $ ./shlayer-cleanup.sh --autoremove

To download and execute this script directly from this repository you can run the following one-liner. (Be careful and review the script before doing this)

    $ curl -s https://raw.githubusercontent.com/carbonblack/tau-tools/master/remediation/shlayer/shlayer-cleanup.sh | bash -s -- --autoremove

To execute this script using Carbon Black's Live Response, add 'execfg' to the beginning of the string.

##### Example

![image](https://user-images.githubusercontent.com/727732/52649660-ecde8b80-2ea5-11e9-81f8-0f9dce1d187d.png)
