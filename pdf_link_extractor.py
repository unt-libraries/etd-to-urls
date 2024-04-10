#!/usr/bin/env python3

import argparse
import mimetypes
import os
import re
import warnings

from poppler import load_from_file
import requests


# TODO: Currently I don't think this will find an URL split before the
# end of the scheme

# Silence requests from complaining about ignoring SSL certs.
warnings.simplefilter('ignore', requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Build a list of common file extensions on the web.
more_extensions = ['.ashx', '.asp', '.aspx', '.cfm', '.jsp', '.php', '.xlsx']
EXTENSIONS = list(mimetypes.types_map) + list(mimetypes.common_types) + more_extensions

DOI_SITE = 'https://doi.org/'  # convert DOIs by replacing doi: with this

# Match a scheme at the end of a line or followed by any number of permitted characters
# that may or may not be within parentheses, but the last character may not be:
# '?', '!', ':', ',', nor '.' (also can't be a space).
# Currently this matches ftp://, but it won't include them in the
# final URL list, since requests doesn't handle the protocol.
URL_MATCHER = re.compile(r'''\b(?:(?:https?|ftp)://|www\.|ftp\.|doi:\s*)
  (?:
    (?:
      (?:\([-\w+&@#/%=~|$?!:,.]*\)|[-\w+&@#/%=~|$?!:,.])*
      (?:\([-\w+&@#/%=~|$?!:,.]*\)|[-\w+&@#/%=~|$])
    )
    |$
  )''', flags=re.I | re.X)

CONTINUATION_MATCHER = re.compile(
  r'''\s*((?:\([-\w+&@#/%=~|$?!:,.]*\)|[-\w+&@#/%=~|$?!:,.])*
  (?:\([-\w+&@#/%=~|$?!:,.]*\)|[-\w+&@#/%=~|$]))''', flags=re.I | re.X)

SCHEME_MATCHER = re.compile(r'\s*((?:https?|ftp)://|doi:)', flags=re.I)

FOOTNOTE_MATCHER = re.compile(r'\d+\s*((?:https?|ftp)://|doi:)', flags=re.I)

DOI_MATCHER = re.compile(r'^https?://doi\.org/', flags=re.I)

BAD_DOI_MATCHER = re.compile(r'^(https?://doi:|doi:\s*(https?://doi\.org/)?)', flags=re.I)

PAGE_NUM_MATCHER = re.compile(r'^\s+\d+\s*$')

# Pattern to guess at an author (possibly hyphenated) beginning a new citation
AUTHOR_MATCHER = re.compile(r'^[A-Z][a-z]+(-[A-Z][a-z]+)?, ')

# Check for possible file extension at end of URL.
FILE_EXTENSION_MATCHER = re.compile(r'//[^/]*/.*(\.[a-z]{2,})$')

# Match query string or hash at beginning of line, allowing spaces
QUERY_OR_ANCHOR_MATCHER = re.compile(r'^\s*[?#].*')

USER_AGENT = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0'


def get_fulltext(path):
    """Extract text from PDF."""
    pdf_document = load_from_file(path)
    fulltext = ''
    for i in range(pdf_document.pages):
        page = pdf_document.create_page(i)
        text = remove_page_number(page.text())
        fulltext += text
    return fulltext


def remove_page_number(text):
    """Remove last line of text if it looks like a page number."""
    lines = text.strip().split('\n')
    if PAGE_NUM_MATCHER.match(lines[-1]):
        text = '\n'.join(lines[:-1]) + '\n'
    return text


def check_urls(speculative_urls, allow_none=False):
    """Check list of speculative URLs for legit responses.

    `speculative_urls` contains a list of the candidates lists for the
    different URLs that multiline URLs could be.
    `allow_none` indicates whether we want to allow not including any of a
    list_of_urls candidates in the case that none of them include an accepted
    response code, i.e. if none of the list_of_urls would be added to `urls`,
    add them all.
    """
    urls = []
    for list_of_urls in speculative_urls:
        found_success_response = False
        if len(list_of_urls) == 1:
            # Only one URL in the list means we didn't find this to be a
            # multiline URL, so add it to the URLs without a live request.
            urls.append(list_of_urls[0])
            continue
        for url in list_of_urls:
            if '.' not in url.replace('//www.', '//'):
                # This isn't a full URL without a dot (but ignore the www. dot).
                continue
            if check_url(url, list_of_urls):
                urls.append(url)
                found_success_response = True
                # Assume we found the version of the URL we want, and ignore the rest...
                # or not, because the URL could break on a legit path that is not the full URL
                # break
        if not allow_none and not found_success_response:
            # We want to ensure at least one candidate is included for the URL,
            # so though none of the candidates returned an HTTP request we
            # like, we'll include them all, so our crawler can try and hope
            # for a better response.
            for url in list_of_urls:
                # Include the URL unless there is no domain.
                if '.' in url.replace('//www.', '//'):
                    urls.append(url)
    return urls


def check_url(speculative_url,
              list_of_urls,
              user_agent=USER_AGENT):
    """Make a live HEAD request, and check for an OK response."""
    print('Live request to', speculative_url)
    allow_redirects = True
    if DOI_MATCHER.match(speculative_url):
        # Some of the sites that doi.org redirects to will give us a 403 response,
        # so just be happy with the redirect code
        allow_redirects = False
        # But if the DOI URL is non-https it redirects to https, so to avoid
        # a misleading URL, test as https.
        speculative_url = speculative_url.replace('http://', 'https://')
    response = make_head_or_get_request(speculative_url, allow_redirects=allow_redirects)
    if response is None:
        return False
    print(response.status_code)
    if response.status_code == 200:
        if response.history and response.url != speculative_url and response.url in list_of_urls:
            # Don't keep this URL if it redirects to another we are testing.
            return False
        else:
            return True
    if DOI_MATCHER.match(speculative_url) and response.status_code < 400:
        return True
    return False


def make_head_or_get_request(url,
                             user_agent=USER_AGENT,
                             allow_redirects=True):
    """Make a HEAD request, but if the server doesn't like it, use GET."""
    try:
        response = requests.head(url,
                                 headers={'User-Agent': user_agent},
                                 timeout=6,
                                 allow_redirects=allow_redirects,
                                 verify=False)
    except requests.exceptions.ReadTimeout:
        # Looking at errors when trialing this script, often times URLs
        # that would give a read timeout would resolve quickly in a browser.
        # Though this will introduce False URLs in our final list, it will
        # gain some legitimate ones.
        print(url, 'Encountered ReadTimeout; include URL anyway')
        response = requests.Response()
        response.status_code = 200
    except requests.RequestException as err:
        print(url, err)
        # TODO: Should we accept URLs that have a SSLCertVerificationError?
        return None
    if response.status_code == 405:
        try:
            response = requests.get(url,
                                    headers={'User-Agent': user_agent},
                                    timeout=6,
                                    verify=False)
        except requests.exceptions.ReadTimeout:
            # We'll just let this one onto to our final list
            # (see comment on ReadTimeout above).
            print(url, 'Encountered ReadTimeout; include URL anyway')
            response = requests.Response()
            response.status_code = 200
        except requests.RequestException as err:
            print(url, err)
            return None
    return response


def preen_url(url):
    """Clean up a URL.

    Add a scheme if missing. Convert DOIs to doi.org URL.
    """
    if BAD_DOI_MATCHER.match(url):
        # Sometimes people incorrectly put an https:// in front of doi: or after.
        url = re.sub(BAD_DOI_MATCHER, DOI_SITE, url)
    if DOI_MATCHER.match(url):
        # Hack to fix where we created https://doi.org/https://dx.doi.org
        # and similar DOI URLs in the actual text.
        if url.startswith(DOI_SITE+'http'):
            url = url.split('doi.org/', 1)[1]
    if not SCHEME_MATCHER.match(url):
        url = 'http://' + url
    return url


class URLParser():
    """Attempt to find URLs, looking for those that cross line breaks.

    lenient indicates whether to try multiline URLs that are likely the end
    of an URL followed by a name and comma as commonly seen in References
    sections of ETDs.
    """

    def __init__(self, text, lenient=False, validate_urls=True):
        self.text = text
        self.lenient = lenient
        self.urls = []
        self.speculative_urls = []
        self.check_multiline = False
        self.multiline_url = ''
        self.process_text(validate_urls)

    def process_text(self, validate_urls=True):
        """Read text line by line to find URLs."""
        for line in self.text.split('\n'):
            self.check_line(line)

        # print(self.speculative_urls)
        if validate_urls:
            validated_urls = check_urls(self.speculative_urls)
            self.urls.extend(validated_urls)
        else:
            for url_variations in self.speculative_urls:
                self.urls.extend(url_variations)
        self.urls = list(set(self.urls))

    def check_line(self, line):
        """Check the line for URLs, either continuing a multiline URL or not."""
        if self.check_multiline:
            self.try_multiline(line)
        elif FOOTNOTE_MATCHER.match(line):
            # This looks like a footnote. Remove leading number for URL checking.
            self.check_line(re.sub(r'^\d+', '', line))
        else:
            # Check the line fresh (not as a URL continuation line or footnote URL).
            line_urls = URL_MATCHER.findall(line)
            if not line_urls:
                # No URLs were found in this line.
                return
            if len(line_urls) > 1:
                # If there are multiple URLs in a line, assume all but the last are ok
                # if they at least appear to have a domain.
                for url in line_urls[:-1]:
                    if '.' in url:
                        self.urls.append(preen_url(url))
            # For URLs at the end of a line, it could be a single or multi-line URL.
            if line.endswith(line_urls[-1] + '.'):
                # Handle special case of a possible multiline URL ending in a '.'
                # on its first line. The dot could be part of an URL split by a line break.
                # Since our regex assumed it was a full stop and didn't include it in the URL, add
                # it back.
                if '.' in line_urls[-1]:
                    # This could be a multiline URL, but it may just be an URL then a full stop.
                    # Add the URL without the line ending dot to speculative URLs,
                    # then check it further with the dot.
                    self.speculative_urls.append([preen_url(line_urls[-1])])
                else:
                    # There was not a dot before the line ending dot, so the line ending dot
                    # must be part of the URL. Create a list for the speculative URLs for
                    # this instance, but don't add what we found on the first line because it
                    # has no domain and can't be the full URL.
                    self.speculative_urls.append([])
                line_urls[-1] = line_urls[-1] + '.'
            if line.endswith(line_urls[-1]):
                self.check_multiline = True
                self.multiline_url = line_urls[-1]
                # With the exception of an URL currently ending in a dot or scheme,
                # put this one in speculative_urls, in case it is the full URL.
                if not line_urls[-1].endswith('.') and not SCHEME_MATCHER.fullmatch(line_urls[-1]):
                    self.speculative_urls.append([preen_url(line_urls[-1])])
                elif SCHEME_MATCHER.fullmatch(line_urls[-1]):
                    # The first line of the URL only has the scheme, so create a list
                    # to place speculative URLs, but don't add the scheme-only string.
                    self.speculative_urls.append([])
            else:
                # This shouldn't be a multiline URL, so add it to urls and move on.
                if '.' in line_urls[-1]:
                    self.urls.append(preen_url(line_urls[-1]))

    def try_multiline(self, line):
        """Determine whether to build onto an already started URL or process fresh."""
        if (
            (not self.lenient and AUTHOR_MATCHER.match(line))
            or SCHEME_MATCHER.match(line)
            or FOOTNOTE_MATCHER.match(line)
        ):
            # If not running in lenient mode, since this looks like the
            # start of a citation or the start of a new URL, assume we are done
            # finding the URL, and process it normally.
            self.reset_multiline(line)
            return
        elif FILE_EXTENSION_MATCHER.search(self.multiline_url):
            # If there was a file extension ending the previous line
            # that indicates we probably found the URL's end there,
            # unless a ? or # beginning the next line could indicate a URL
            # still going, assume we are not in a multiline URL.
            if FILE_EXTENSION_MATCHER.search(self.multiline_url).group(1) in EXTENSIONS:
                if not QUERY_OR_ANCHOR_MATCHER.match(line):
                    # We matched a file extension and it looks like the
                    # current line isn't adding a query string or anchor,
                    # so assume we are not still in a multiline url and
                    # process normally.
                    self.reset_multiline(line)
                    return

        # Check for punctuation/whitespace indicating
        # where the URL would end if this is a multiline URL.
        # Also, it could continue to another line again.
        match = CONTINUATION_MATCHER.match(line)
        if match:
            # Add group 1 to the speculative multiline URL to ignore whitespace
            # that may exist at the beginning of a line, such as with an indented
            # portion of a reference citation, and add to speculative_urls
            # to check.
            self.multiline_url += match.group(1)
            self.speculative_urls[-1].append(preen_url(self.multiline_url))
            if match.group(0) != line:
                # If the full line doesn't match a continuing URL,
                # we came to the end of where the URL might extend, so
                # reset things and check the line further for other URLs.
                self.reset_multiline(line)

    def reset_multiline(self, line):
        """Reset multiline related variables and re-check line.

        After detecting the end of a multiline URL, clear out the URL
        we were building, and check the line for further URLs.
        """
        self.multiline_url = ''
        self.check_multiline = False
        self.check_line(line)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        dest='input',
        nargs='+',
        action='store',
        help='Input is a list of PDF files',
    )
    parser.add_argument(
        '-o', '--output',
        dest='output_dir',
        action='store',
        help='Output directory for URL files.',
        default=os.getcwd()
    )
    parser.add_argument(
        '-n', '--no-validate',
        dest='no_validate',
        action='store_true',
        help='Skip live URL request checking.'
    )
    parser.add_argument(
        '-s', '--sort',
        action='store_true',
        help='Sort URL output.'
    )
    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    validate = True
    if args.no_validate:
        validate = False

    SUBMISSION_MATCHER = re.compile(r'(submission_[^/]+/[^/]+\.pdf)',
                                    flags=re.I)

    for path in args.input:
        print('Processing', path)
        url_parser = URLParser(get_fulltext(path), validate_urls=validate)
        matched_path = SUBMISSION_MATCHER.search(path)
        if matched_path:
            # Structure the output in submission subdirectories like the pdfs
            output_path = os.path.join(args.output_dir, matched_path.group(1)+'.urls')
            submission_dir = os.path.dirname(output_path)
            if not os.path.exists(submission_dir):
                os.makedirs(submission_dir)
        else:
            output_path = os.path.join(args.output_dir, os.path.basename(path)+'.urls')
        urls = url_parser.urls
        if args.sort:
            urls = sorted(urls)
        with open(output_path, 'w') as urls_file:
            urls_file.write('\n'.join(urls))


if __name__ == '__main__':
    main()
