import os
import glob
import math
from datetime import datetime
from collections import Counter
import dns.resolver
import whois
import tldextract


def domains_filter(domains):
    domains = [*set(domains)]
    filtered_domains = []
    for domain in domains:
        if domain.startswith("www."):
            filtered_domains.append(domain[4:])
        else:
            filtered_domains.append(domain)
    return [*set(filtered_domains)]

def search_models(model_dir, model_path):
    models = []
    if not os.path.isdir(model_dir):
        os.mkdir(model_dir)
    else:
        models = list(filter(os.path.isfile, glob.glob(model_path)))
        models.sort(key=lambda x:os.path.getmtime(x))
    return models


def check_user_input():
    user_answer = input("Do you want to train the model now? (y/n): ")
    user_answer = user_answer.lower()
    
    while user_answer != 'y' and user_answer != 'n':
        print("Please enter a 'y' for yes and a 'n' for no.")
        user_answer = input("Do you want to train the model now? (y/n): ")
        user_answer = user_answer.lower()
    
    return user_answer


def extract_sld(domain):
    extracted = tldextract.extract(domain)
    return extracted.domain


def calculate_entropy(text):
    char_freq = {}
    text_length = len(text)

    for char in text:
        if char in char_freq:
            char_freq[char] += 1
        else:
            char_freq[char] = 1

    entropy = 0.0
    for freq in char_freq.values():
        probability = freq / text_length
        entropy -= probability * math.log2(probability)
    return entropy


def calculate_char_distribution(text):
    char_counts = Counter(text)
    total_chars = len(text)
    char_dist = {char: char_counts[char] / total_chars for char in char_counts}
    return char_dist


def get_domain_ttl(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ttl = answers.rrset.ttl
        return ttl
    except dns.resolver.NXDOMAIN:
        return -1
    except dns.resolver.NoAnswer:
        return -2
    except dns.exception.DNSException as e:
        return -3
    

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date is not None:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            if isinstance(creation_date, str):
                if creation_date.lower() == "before":
                    return -1  # creation date is not available
                creation_date = datetime.strptime(creation_date.split()[0], "%Y-%m-%d")
            age = datetime.now() - creation_date
            return age.days
        else:
            return -1  # No whois entry
    except whois.parser.PywhoisError:
        return -1  
    except UnicodeError:
        return -1  
