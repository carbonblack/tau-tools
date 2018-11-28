# powershell_meterpreter_extractor

## Synopsis

    This project is for extracting base64 encoded shellcode used to deliver Meterpreter payloads.

## Usage Help

    python powershell_meterpreter_extractor.py --help
    usage: powershell_meterpreter_extractor.py [-h] [-o OUTPUT] (-i INPUT | -f FILE)

    optional arguments:
      -h, --help            show this help message and exit
      -o OUTPUT, --output OUTPUT
                            Provide a path to save final stage payload
      -i INPUT, --input INPUT
                            Provide a base64 encoded string in the command line
      -f FILE, --file FILE  Provide a path to a file that contains a base64
                            encoded string

## Usage Example

 The following will accept an input file containing the base64 encoded string and output the first and second stage to disk: 

    ./powershell_meterpreter_extractor.py -f <input file> -o <output file>

 The following will accept a base64 string passed as a cmd line arg and output text to terminal:

    ./powershell_meterpreter_extractor.py -i <base64 encoded string>

## History

    Version 1.0 - Initial release

## Author
 
 Adam Nadrowski (anadrowski@carbonblack.com)
 
 Jared Myers (jmyers@carbonblack.com)

## License

    The MIT License (MIT)

    Copyright (c) 2018 Carbon Black

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
