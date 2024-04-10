# ETD to URLs

The goal of ETD to URLs is to extract URLs from Electronic Theses and Dissertations to faciliate
making a small web capture of the URLs referenced in these documents that can be added to the
items deposited in the UNT Digital Library as a way of being able to view content referenced in
these publications.

etd-to-urls includes a Python script pdf_link_extractor.py that converts PDF files to text
using [python-poppler](https://cbrunet.net/python-poppler/), a Python wrapper for Poppler which
provides the tools `pdftohtml` and `pdftotext`, and extracts URLs found. We include logic to
potentially improve results for deciding whether URLs run over multiple lines over simply
converting to text or HTML and using a regular expression alone.

After generating a list of URLs with pdf_link_extractor.py, a web archive in the form of a
WACZ file may be produced by modifying and running the include browsertrix-crawl.sh script.

Generating URL lists
--------------------
With the flexibility allowed in what goes into an URL, knowing whether an URL spans
to a second or more lines is difficult to determine with regular expression alone.
Thus, for each string that looks like an URL that this script finds, if the URL runs to
the end of a line, a list of possible URLs is made. If there is more than one possibility
after using heuristics to weed out what is most likely not an URL (based on if it looks like
the next line has an Author starting a citation, or the URL ends with a known file extension)
the different possibilities are tried via live web request and depending on the response code,
they are added to the list of URLs. Live requests are not made for URLs that were fully contained
in a line. Live request checking can be disabled via commandline argument when running
pdf_link_extractor.py and all possible versions of an URL will be included in the URL list.

Setup
-----
- Install [libpoppler](https://poppler.freedesktop.org/) and make sure it is on your system path
(if you don't install from package manager).
- Install the Python libraries [python-poppler](https://cbrunet.net/python-poppler/) and requests
with pip.

Usage
-----
To run pdf_link_extractor.py, give it one or multiple PDF files and an output directory. If the
PDFs are in individual directories named starting with "submission_", the output URLs files
will retain that submission directory structure. Otherwise, output .urls files will be in a
flat directory.

example:

    $ python3 experiment-06-poppler/lauren/pdf_link_extractor.py data/2023-May/*/*.pdf -o output > 2023-May.log

```
usage: pdf_link_extractor.py [-h] [-o OUTPUT_DIR] [-n] [-s] input [input ...]

positional arguments:
  input                 Input is a list of PDF files

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_DIR, --output OUTPUT_DIR
                        Output directory for URL files.
  -n, --no-validate     Skip live URL request checking.
  -s, --sort            Sort URL output.
```

Crawling
--------
Once .urls files are created for each PDF (via pdf_link_extractor.py or by other means),
a WACZ can be created for each .urls file by running
a script like the browsertrix-crawl.sh script in the root of this repo. This script loops over
the .urls files supplied via commandline argument and runs a
[browsertrix-crawler](https://github.com/webrecorder/browsertrix-crawler)
crawl for each in docker. Once you have docker installed, pull down browsertrix-crawler then
you can run the crawls.

    $ docker pull webrecorder/browsertrix-crawler
    $ etd-to-urls/browsertrix-crawl.sh >> browsertrix-crawl_20230703.log

Testing
-------
To run included tests, install pytest and from the root of this repo run:

    $ pytest ./test_pdf_link_extractor.py
