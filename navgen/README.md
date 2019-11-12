# Navigator Generator (NavGen)

## Synopsis

This project is for generating a MITRE Navigator JSON file that can be used to upload to an on-prem or github instance (https://mitre.github.io/attack-navigator/enterprise/).

## Usage Example

    python navgen.py
	[!] To find your API key, login to your Cb Response UI and navigate to the profile section.
	[!] Here, enter the full url of your Cb Response instance. Example: https://bugcrowd.my.carbonblack.io
	[*] > https://testing-instance.my.carbonblack.io
	[*] Enter your API key: > 400389f1ac4195c978bdce6c9a5421ce1185bba2
	
	Your url is: https://testing-instance.my.carbonblack.io
	Your API key is: 400389f1ac4195c978bdce6c9a5421ae1185bba2
	There are 515 total threat reports found.
	
	[!] Saved MITRE Navigator json file as CbResponseNavigator-1543418603.json
	[!] Use this file to 'Open Existing Layer' from local file on https://mitre.github.io/attack-navigator/enterprise/

## History

Version 1.0 - Initial release

## Author
 
Adam Nadrowski ([@\_sup\_mane](https://twitter.com/_sup_mane))      
Jimmy Astle

## License

    The MIT License (MIT)

    Copyright (c) 2018 Carbon Black

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
