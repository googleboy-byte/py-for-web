import requests
import argparse
from pprint import pprint
from bs4 import BeautifulSoup as bs
from requests_html import HTMLSession
from urllib.parse import urljoin, urlparse
import colorama

# site for testing code: http://testphp.vulnweb.com/artists.php?artist=1


colorama.init()

GREEN = colorama.Fore.GREEN
GRAY = colorama.Fore.LIGHTBLACK_EX
RED = colorama.Fore.RED
RESET = colorama.Fore.RESET

internal_urls = set()
external_urls = set()

total_urls_visited = 0


def is_valid(url):
    """
    Checks whether `url` is a valid URL.
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)




def get_all_website_links(url):
    urls = set()
    domain_name = urlparse(url).netloc
    session = HTMLSession()
    # make HTTP request & retrieve response
    response = session.get(url)
    # execute Javascript
    try:
        response.html.render()
    except:
        pass
    soup = bs(response.html.html, "html.parser")
    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            # href empty tag
            continue
        # join the URL if it's relative (not absolute link)
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        # remove URL GET parameters, URL fragments, etc.
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if not is_valid(href):
            # not a valid URL
            continue
        if href in internal_urls:
            # already in the set
            continue
        if domain_name not in href:
            # external link
            if href not in external_urls:
                #print(f"{GRAY}[!] External link found: {href}{RESET}")
                external_urls.add(href)
            continue
        print(f"{GREEN}[*] Internal link found: {href}{RESET}")
        urls.add(href)
        internal_urls.add(href)
    return urls


def get_site_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    #print(soup.find_all("form"))
    return soup.find_all("form")    

def get_form_properties(form):
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
        
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url,  value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        
        input_name = input.get("name")
        input_value = input.get("value")
        
        if input_name and input_value:
            data[input_name] =  input_value
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)

def scan_for_xss(webaddrs):
    print(f"\n[*]Checking site '{webaddrs}' for Cross Site Scripting(XSS) Vulnerabilities\n")
    forms = get_site_forms(webaddrs)
    print(len(forms), "form(s) detected on url \" ", webaddrs,"\"")
    java_script = "<script>alert('XSS')</script>"
    site_is_vuln  = False
    for form  in forms:
        form_details = get_form_properties(form)
        content = submit_form(form_details, webaddrs, java_script).content.decode()
        if  java_script in content:
            print(f"\n{RED}XSS DETECTED!!!\n\nSite Vulnerable to Cross Site Scripting{RESET} ")
            site_is_vuln = True
            print(f"\n{RED}FORM DETAILS: \n{RESET}")
            pprint(form_details)
    
    return site_is_vuln

def is_vuln_sql(response):
    a = 0
    errors = {
        "you have an error in your sql syntax;", # running my sql
        "warning: mysql", # running mysql
        "unclosed quotation mark after the character string", # running SQL Server
        "quoted string not properly terminated", # running Oracle
        }
    for error in errors:
        a = a + 1
        if error in response.content.decode().lower():
            if a == 1:
                print(f"\n{RED}Type of database: MySQL{RESET}")
            elif a == 2:
                print(f"\n{RED}Type of database: MySQL{RESET}")
            elif a == 3:
                print(f"\n{RED}Type of database: SQL Server{RESET}")
            elif a == 4:
                print(f"\n{RED}Type of database: Oracle{RESET}")
            return True
    return False

def scan_for_sql(url):
    for c in "\"'":
        url1 = f"{url}{c}"
        print("\n[*]Checking for sql injection on site: " + url1)
        res = requests.get(url1)
        if is_vuln_sql(res):
            print(f"{RED}\nSite Vulnerable to SQL INJECTION!!!\n{RESET}")
            print(f"{RED}Link: {RESET}", f"{RED}{url1}{RESET}", "\n")
            return
    forms = get_site_forms(url)
    print(f"\n{len(forms)} forms detected on site {url}.")
    for form in forms:
        form_details = get_form_properties(form)
        for i in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] == input_tag["value"] + i
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{i}"
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = requests.post(url, data=data)
            elif  form_details["method"] == "get":
                res = requests.get(url, params=data)
            if is_vuln_sql(res):
                print(f"\n{RED}Site vulnerable to SQL INJECTION!!!!{RESET}")
                print(f"\n{RED}Site link: {RESET}", f"{RED}{url}{RESET}", "\n")
                pprint(form_details)
                break



def crawl(url, max_urls=30):
    global total_urls_visited
    total_urls_visited += 1
    links = get_all_website_links(url)
    for link in links:
        if total_urls_visited > max_urls:
            print('---------------------------------------------------------------------')
            break
        crawl(link, max_urls=max_urls)
                

def main(url, max_urls=30):
    e_links = []
    crawl(url, max_urls=max_urls)
    
    print("[+] Total Internal links:", len(internal_urls))
    print("[+] Total External links:", len(external_urls))
    print("[+] Total URLs:", len(external_urls) + len(internal_urls))
    
    domain_name = urlparse(url).netloc
    a = 0
    # save the internal links to a file
    for internal_link in internal_urls:
        try:
            scan_for_sql(internal_link)
        except:
            print("\nSite does NOT appear vulnerable to SQL Injection")
        try:
            print(scan_for_xss(internal_link))
        except:
            print("\nSite does NOT appear vulnerable to Cross Site Scripting(XSS)")
    
    # save the external links to a file
    for external_link in external_urls:
        e_links.append(external_link)
    

if __name__ == "__main__":
    print()
    site = input("Base site url to perform vulnerability detection: ")
    parser = argparse.ArgumentParser()
    parser.add_argument("-op", "--one_page", default=False)
    args = parser.parse_args()
    if args.one_page:
        try:
            scan_for_sql(site)
        except:
            print("\nSite does NOT appear vulnerable to SQL Injection")
        try:
            print(scan_for_xss(site))
        except:
            print("\nSite does NOT appear vulnerable to Cross Site Scripting(XSS)")
    else:
        main(site)
