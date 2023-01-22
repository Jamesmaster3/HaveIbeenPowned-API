import requests
import hashlib
import sys


def pwn_api_check(password):
    # hash paswords using hashlib, only send first 5 characters to API
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_pasword_leaks_count(response, tail)


def request_api_data(query_char):
    # connect to API and check first 5 characters of hash, returns matching values
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the API and try again')
    return res


def get_pasword_leaks_count(hashes, hash_to_check):
    # hashes are the returned hashed passwords from API with similair first 5 charachters
    # split hash in returned hash and times it was found

    hashes = (line.split(":") for line in hashes.text.splitlines())
    # only print out count for inputted pasword
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def main():
    args = input(
        'Input passwords to check if it has been hacked. Check multiple passwords by separating with a space. ')
    args = args.split(' ')
    for password in args:
        count = pwn_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... You should probably change your password')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'Done!'


if __name__ == '__main__':
    main()
