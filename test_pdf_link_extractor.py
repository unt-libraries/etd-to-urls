from unittest.mock import call, patch, Mock

from requests import ReadTimeout, RequestException

import pdf_link_extractor as ple


@patch('pdf_link_extractor.load_from_file')
def test_get_fulltext(m_load):
    document = Mock(pages=2)
    document.create_page.return_value.text.return_value = 'hello\n 1\n'
    m_load.return_value = document
    path = 'path/to/some.pdf'
    fulltext = ple.get_fulltext(path)
    # Verify we got two pages of text and removed the page numbers.
    assert fulltext == 'hello\nhello\n'
    m_load.assert_called_once_with(path)


def test_remove_page_number():
    text = ('This is a page\n'
            'with text\n'
            'ending with a page number\n'
            '       98\n')
    output = ple.remove_page_number(text)
    assert output == ('This is a page\n'
                      'with text\n'
                      'ending with a page number\n')


def test_no_remove_page_number():
    text = ('This is a page\n'
            'with text\n'
            'ending without a page number\n')
    output = ple.remove_page_number(text)
    assert output == text


@patch('pdf_link_extractor.check_url', return_value=True)
def test_check_urls(m_check_url):
    speculative = [['http://www.unt', 'http://www.unt.edu/about'],
                   ['http://library.unt.edu']]
    urls = ple.check_urls(speculative)
    assert urls == ['http://www.unt.edu/about',
                    'http://library.unt.edu']
    m_check_url.assert_called_once_with('http://www.unt.edu/about', speculative[0])


@patch('pdf_link_extractor.requests.head')
def test_check_urls_redirect_to_other_variant(m_head):
    speculative_urls = [['https://example.com/some-long-',
                         'https://example.com/some-long-article-name']]
    m_head.side_effect = [Mock(history=speculative_urls[0][0],
                               url=speculative_urls[0][1],
                               status_code=200),
                          Mock(status_code=200)]
    # Since the first speculative url redirects to another in the list, just add one redirected to.
    urls = ple.check_urls(speculative_urls)
    assert urls == [speculative_urls[0][1]]
    calls = [call(speculative_urls[0][0],
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=True,
                  verify=False),
             call(speculative_urls[0][1],
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=True,
                  verify=False)]
    m_head.assert_has_calls(calls)


@patch('pdf_link_extractor.check_url', return_value=False)
def test_check_urls_no_valid_candidates_allow_none(m_check_url):
    speculative = [['http://www.unt', 'http://www.unt.edu/about'],
                   ['http://library.unt.edu']]
    urls = ple.check_urls(speculative, allow_none=True)
    assert urls == ['http://library.unt.edu']
    m_check_url.assert_called_once_with('http://www.unt.edu/about', speculative[0])


@patch('pdf_link_extractor.check_url', return_value=False)
def test_check_urls_no_valid_candidates_allow_none_false(m_check_url):
    speculative = [['http://www.unt', 'http://www.unt.edu/about'],
                   ['http://library.unt.edu']]
    urls = ple.check_urls(speculative, allow_none=False)
    assert urls == ['http://www.unt.edu/about', 'http://library.unt.edu']
    m_check_url.assert_called_once_with('http://www.unt.edu/about', speculative[0])


@patch('pdf_link_extractor.requests.head')
def test_check_url_redirect_to_other_variant(m_head):
    list_of_urls = ['https://example.com/some-long-',
                    'https://example.com/some-long-article-name']
    m_head.side_effect = [Mock(history=list_of_urls[0], url=list_of_urls[1], status_code=200),
                          Mock(status_code=200)]
    # Since the first speculative url redirects to another in the list, don't use it.
    assert not ple.check_url(list_of_urls[0], list_of_urls)
    # The one that is redirected to should be added.
    assert ple.check_url(list_of_urls[1], list_of_urls)
    calls = [call(list_of_urls[0],
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=True,
                  verify=False),
             call(list_of_urls[1],
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=True,
                  verify=False)]
    m_head.assert_has_calls(calls)


@patch('pdf_link_extractor.make_head_or_get_request', return_value=None)
def test_check_url_no_response(m_request):
    list_of_urls = ['ftp://example.com/about-', 'ftp://example.com/about-us']
    assert not ple.check_url(list_of_urls[0], list_of_urls)
    m_request.assert_called_once_with('ftp://example.com/about-',
                                      allow_redirects=True)


@patch('pdf_link_extractor.requests.head', return_value=Mock(status_code=200))
def test_make_head_or_get_request_head(m_head):
    agent = 'python script'
    response = ple.make_head_or_get_request('http://example.com',
                                            user_agent=agent)
    assert response == m_head.return_value
    m_head.assert_called_once_with('http://example.com',
                                   headers={'User-Agent': agent},
                                   timeout=6,
                                   allow_redirects=True,
                                   verify=False)


@patch('pdf_link_extractor.requests.head', side_effect=ReadTimeout)
def test_make_head_or_get_request_head_read_timeout(m_head):
    agent = 'python script'
    response = ple.make_head_or_get_request('http://example.com',
                                            user_agent=agent)
    assert response.status_code == 200
    m_head.assert_called_once_with('http://example.com',
                                   headers={'User-Agent': agent},
                                   timeout=6,
                                   allow_redirects=True,
                                   verify=False)


@patch('pdf_link_extractor.requests.head', side_effect=RequestException)
def test_make_head_or_get_request_head_other_error(m_head):
    agent = 'python script'
    response = ple.make_head_or_get_request('http://example.com',
                                            user_agent=agent)
    assert response is None
    m_head.assert_called_once_with('http://example.com',
                                   headers={'User-Agent': agent},
                                   timeout=6,
                                   allow_redirects=True,
                                   verify=False)


@patch('pdf_link_extractor.requests.head', return_value=Mock(status_code=405))
@patch('pdf_link_extractor.requests.get', return_value=Mock(status_code=200))
def test_make_head_or_get_request_405(m_get, m_head):
    agent = 'python script'
    response = ple.make_head_or_get_request('http://example.com',
                                            user_agent=agent)
    assert response == m_get.return_value
    m_head.assert_called_once_with('http://example.com',
                                   headers={'User-Agent': agent},
                                   timeout=6,
                                   allow_redirects=True,
                                   verify=False)
    m_get.assert_called_once_with('http://example.com',
                                  headers={'User-Agent': agent},
                                  timeout=6,
                                  verify=False)


@patch('pdf_link_extractor.requests.head', return_value=Mock(status_code=405))
@patch('pdf_link_extractor.requests.get', side_effect=ReadTimeout)
def test_make_head_or_get_request_405_read_timeout(m_get, m_head):
    agent = 'python script'
    response = ple.make_head_or_get_request('http://example.com',
                                            user_agent=agent)
    assert response.status_code == 200
    m_head.assert_called_once_with('http://example.com',
                                   headers={'User-Agent': agent},
                                   timeout=6,
                                   allow_redirects=True,
                                   verify=False)
    m_get.assert_called_once_with('http://example.com',
                                  headers={'User-Agent': agent},
                                  timeout=6,
                                  verify=False)


@patch('pdf_link_extractor.requests.head', return_value=Mock(status_code=405))
@patch('pdf_link_extractor.requests.get', side_effect=RequestException)
def test_make_head_or_get_request_405_error(m_get, m_head):
    agent = 'python script'
    response = ple.make_head_or_get_request('http://example.com',
                                            user_agent=agent)
    assert response is None
    m_head.assert_called_once_with('http://example.com',
                                   headers={'User-Agent': agent},
                                   timeout=6,
                                   allow_redirects=True,
                                   verify=False)
    m_get.assert_called_once_with('http://example.com',
                                  headers={'User-Agent': agent},
                                  timeout=6,
                                  verify=False)


def test_preen_url_doi():
    url = 'doi:10.1016/S0020-7462(02)00027-6'
    preened_url = ple.preen_url(url)
    assert preened_url == 'https://doi.org/10.1016/S0020-7462(02)00027-6'


def test_preen_url_doi_http_and_space():
    url = 'doi: https://doi.org/10.1016/S0020-7462(02)00027-6'
    preened_url = ple.preen_url(url)
    assert preened_url == 'https://doi.org/10.1016/S0020-7462(02)00027-6'


def test_preen_url_no_scheme():
    url = 'www.site.com'
    preened_url = ple.preen_url(url)
    assert preened_url == 'http://www.site.com'


def test_preen_url_no_change():
    url = 'https://doi.org/10.1016/S0020-7462(02)00027-6'
    preened_url = ple.preen_url(url)
    assert preened_url == url


def test_preen_url_doi_bad():
    url = 'https://doi:10.1016/S0020-7462(02)00027-6'
    preened_url = ple.preen_url(url)
    assert preened_url == 'https://doi.org/10.1016/S0020-7462(02)00027-6'


def test_URLParser_multiple_urls_on_single_line():
    url_parser = ple.URLParser(
        'Here is some text\n'
        'with https://google.com, www.unt.edu, doi:10.1234/233432-x-P12 not url\n'
    )
    assert set(url_parser.urls) == set(['https://google.com',
                                        'http://www.unt.edu',
                                        'https://doi.org/10.1234/233432-x-P12'])


@patch('pdf_link_extractor.requests.head', side_effect=[Mock(status_code=404),
                                                        Mock(status_code=302)])
def test_URLParser_multiple_urls_over_single_line(m_head):
    url_parser = ple.URLParser(
        'Here is some text\n'
        'with https://google.com, www.unt.edu, doi:10.1234/233432-x-\n'
        '    P12 not url\n'
    )
    assert set(url_parser.urls) == set(['https://google.com',
                                        'http://www.unt.edu',
                                        'https://doi.org/10.1234/233432-x-P12'])
    # Requests are not made for google.com and unt.edu because they are fully
    # contained within the line of text.
    calls = [call('https://doi.org/10.1234/233432-x-',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=False,
                  verify=False),
             call('https://doi.org/10.1234/233432-x-P12',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=False,
                  verify=False)]
    m_head.assert_has_calls(calls)


@patch('pdf_link_extractor.requests.head', side_effect=[Mock(status_code=404),
                                                        Mock(status_code=302)])
def test_URLParser_multiline_last_line_contains_another_url(m_head):
    """Test finding a new URL after the end of a multiline URL on the same line."""
    url_parser = ple.URLParser(
        'Here is some text\n'
        'with https://google.com, www.unt.edu, doi:10.1234/233432-x-\n'
        '    P12 not url text. Then also http://www.example.com.\n'
    )
    assert set(url_parser.urls) == set(['https://google.com',
                                        'http://www.unt.edu',
                                        'https://doi.org/10.1234/233432-x-P12',
                                        'http://www.example.com'])
    # Requests are not made for google.com and unt.edu because they are fully
    # contained within the line of text.
    calls = [call('https://doi.org/10.1234/233432-x-',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=False,
                  verify=False),
             call('https://doi.org/10.1234/233432-x-P12',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=False,
                  verify=False)]
    m_head.assert_has_calls(calls)


@patch('pdf_link_extractor.requests.head', side_effect=[Mock(status_code=404),
                                                        Mock(status_code=200)])
def test_URLParser_first_line_of_multiline_ends_in_dot(m_head):
    # Verify we try the case where the dot is a full stop of a sentence
    # and as part of an ongoing multiline URL.
    url_parser = ple.URLParser(
        'Some text. Then also http://alpha.example.\n'
        'com/path is a website.'
    )
    assert set(url_parser.urls) == set(['http://alpha.example.com/path'])
    calls = [call('http://alpha.example',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=True,
                  verify=False),
             call('http://alpha.example.com/path',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=True,
                  verify=False)]
    m_head.assert_has_calls(calls)


def test_URLParser_first_line_of_multiline_ends_in_dot_full_stop():
    # Verify we try the case where the dot is a full stop in citation
    # section.
    url_parser = ple.URLParser(
        'vol. 28, no. S1, pp. 1648–1649, Aug. 2022, doi: 10.1017/S1431927622006560.\n'
        '\n'
        '[40]   P. Cavaliere, "Hydrogen Embrittlement: Damage Mechanisms," in Hydrogen\n'
        '\n'
        '       Embrittlement in Metals and Alloys, Cham: Springer Nature Switzerland, 2025',
        validate_urls=False
    )
    assert set(url_parser.urls) == set(['https://doi.org/10.1017/S1431927622006560'])


@patch('pdf_link_extractor.requests.head')
def test_URLParser_first_line_of_multiline_ends_in_first_dot_of_url(m_head):
    # Verify we don't try the URL before we get to atleast one dot because
    # we don't have a domain yet in that case.
    url_parser = ple.URLParser(
        'Some text. Then also http://alpha.\n'
        'example.com/path is a website.'
    )
    assert set(url_parser.urls) == set(['http://alpha.example.com/path'])
    # Verify we don't make a request because there was only one speculative URL.
    m_head.assert_not_called()


@patch('pdf_link_extractor.requests.head')
def test_URLParser_first_line_of_multiline_has_scheme_only(m_head):
    # Verify we find multiline URLs split after the scheme.
    url_parser = ple.URLParser(
        'Some text. Then also https://\n'
        'alpha.example.com/path is a website.'
    )
    assert set(url_parser.urls) == set(['https://alpha.example.com/path'])
    # Verify we don't make a request because there was only one speculative URL.
    m_head.assert_not_called()


@patch('pdf_link_extractor.requests.head')
def test_URLParser_scheme_only_not_included_as_url(m_head):
    # Verify a scheme in the middle of a line isn't included as an URL.
    url_parser = ple.URLParser(
        'Schemes for are URLs are http://, https:// and doi:.'
    )
    assert not url_parser.urls
    # Verify we don't make a request.
    m_head.assert_not_called()


@patch('pdf_link_extractor.requests.head')
def test_URLParser_url_followed_by_author(m_head):
    url_parser = ple.URLParser(
        'Here is some text\n'
        'Apple, Green. Blah. https://google.com\n'
        'Beem, Rail. A title etc. doi:10.1234/233432-x-P12\n'
        'Doe, John. Stuff.\n'
    )
    assert set(url_parser.urls) == set(['https://google.com',
                                        'https://doi.org/10.1234/233432-x-P12'])
    # Verify no requests were made, because the URLs weren't tested as multiline URLs.
    m_head.assert_not_called()


@patch('pdf_link_extractor.requests.head', side_effect=[Mock(status_code=404),
                                                        Mock(status_code=200)])
def test_URLParser_url_followed_by_scheme(m_head):
    url_parser = ple.URLParser(
        'Here is some text\n'
        'Apple, Green. Blah. https://google.com\n'
        'doi:10.1234/233432-x-P12\n'
        'http://something.com/all-in-\n'
        'some-end (2000)'
    )
    assert set(url_parser.urls) == set(['https://google.com',
                                        'https://doi.org/10.1234/233432-x-P12',
                                        'http://something.com/all-in-some-end'])
    # Verify requests were only made for the something.com URL variations,
    # because the others weren't tested as multiline URLs.
    calls = [call('http://something.com/all-in-',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=True,
                  verify=False),
             call('http://something.com/all-in-some-end',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=True,
                  verify=False)]
    m_head.assert_has_calls(calls)


@patch('pdf_link_extractor.check_url')
def test_URLParser_url_with_file_extension(m_check_url):
    url_parser = ple.URLParser(
        'Here is some text\n'
        'Apple, Green. Blah. https://example.com/files/some.pdf\n'
        'This is a new line\n'
    )
    assert url_parser.urls == ['https://example.com/files/some.pdf']
    # No requests were made because the file extension at the end of the URL precluded it.
    m_check_url.assert_not_called()


@patch('pdf_link_extractor.check_url', side_effect=[False, True])
def test_URLParser_url_with_file_extension_and_multiline(m_check_url):
    speculative = ['https://example.com/files/some.pdf',
                   'https://example.com/files/some.pdf?page=1']
    url_parser = ple.URLParser(
        'Here is some text\n'
        'Apple, Green. Blah. https://example.com/files/some.pdf\n'
        '?page=1\n'
    )
    assert url_parser.urls == ['https://example.com/files/some.pdf?page=1']
    m_check_url.has_calls([call('https://example.com/files/some.pdf', speculative),
                           call('https://example.com/files/some.pdf?page=1', speculative)])


@patch('pdf_link_extractor.requests.head', side_effect=[Mock(status_code=302),
                                                        Mock(status_code=404)])
def test_URLParser_doi_with_space(m_head):
    url_parser = ple.URLParser(
        'I used this digital object DOI: 10.1037/0022-0167.48.3.251.\n'
        ' and, this one too doi: 10.1007/s40830-016-0064-1.\n'
        'https://doi.org/10.1007/s40830-017-0129-9 also\n'
        'DOI: https://doi.org/10.888\n'
        'doi:10.1016/S0020-7462(02)00027-6\n'
        'Someone, Ann. doi:https://doi.org/10.984/sldk-x-99\n'
        'doi: http://dx.doi.org/10.1016/j.hjdsi.2016.09.003\n'
        'https://doi.org/https://doi.org/10.1177/000841740507200105\n'
    )
    assert set(url_parser.urls) == set(['https://doi.org/10.1037/0022-0167.48.3.251',
                                        'https://doi.org/10.1007/s40830-016-0064-1',
                                        'https://doi.org/10.1007/s40830-017-0129-9',
                                        'https://doi.org/10.888',
                                        'https://doi.org/10.1016/S0020-7462(02)00027-6',
                                        'https://doi.org/10.984/sldk-x-99',
                                        'http://dx.doi.org/10.1016/j.hjdsi.2016.09.003',
                                        'https://doi.org/10.1177/000841740507200105'])
    calls = [call('https://doi.org/10.1037/0022-0167.48.3.251',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=False,
                  verify=False),
             call('https://doi.org/10.1037/0022-0167.48.3.251.and',
                  headers={'User-Agent': ple.USER_AGENT},
                  timeout=6,
                  allow_redirects=False,
                  verify=False)]
    m_head.assert_has_calls(calls)


@patch('pdf_link_extractor.requests.head', return_value=Mock(status_code=200))
def test_URLParser_footnotes(m_head):
    url_parser = ple.URLParser(
        'last sentence of page before footnote in poppler generated fulltext.\n'
        '1https://1.example.com/ios/app-store/\n'
        '2https://2.example.com/store\n'
        '3Not an URL\n'
        '4https://www.example.com/mobile-apps/b?ie=UTF8&node=2350\n'
    )
    # Note: https://2.example.com/store3Not is in the final URL set because the line started with
    # a number not followed by http, so it was considered as a continuation line of a
    # speculative multiline URL. When it was "live" tested, our mocked response said it was ok.
    assert set(url_parser.urls) == set(['https://1.example.com/ios/app-store/',
                                        'https://2.example.com/store',
                                        'https://2.example.com/store3Not',
                                        'https://www.example.com/mobile-apps/b?ie=UTF8&node=2350'])


def test_URLParser_invalid_URL_fully_contained_in_line_is_not_included():
    # Verify an invalid URL isn't included.
    url_parser = ple.URLParser(
        'URL with typo https://www. accidentalspace.com is not included.'
    )
    assert not url_parser.urls


def test_URLParser_invalid_URL_fully_contained_in_line_with_multiple_urls_not_included():
    # Verify an invalid URL isn't included.
    url_parser = ple.URLParser(
        'Not https://www. accidentalspace.com but include http://example.com.'
    )
    assert url_parser.urls == ['http://example.com']
