import requests
import hashlib
import sys


def password_to_sha1(password):
    """
    convert password to sha1
    :param password:
    :return:
    """
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1pwd


def get_pwned_passwords_from_api(prefix):
    response = requests.get('https://api.pwnedpasswords.com/range/' + prefix)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the api and try again')
    else:
        return response.text


def check_for_pwned_password(pwned_passwords, sha1pwd_tail):
    pwned_password_list = pwned_passwords.splitlines()
    for pwned in pwned_password_list:
        pwd, cnt = pwned.split(':')
        if sha1pwd_tail == pwd:
            return cnt

    return 0


def main(args):
    for pwd in args:
        sha1pwd = password_to_sha1(pwd)
        prefix, tail = sha1pwd[:5], sha1pwd[5:]
        pwned_passwords = get_pwned_passwords_from_api(prefix)
        cnt = check_for_pwned_password(pwned_passwords, tail)
        if cnt != 0:
            print(f'{pwd} was found {cnt} times. You should change your password !')
        else:
            print(f'{pwd} is okay, go on !')


if __name__ == '__main__':
    main(sys.argv[1:])
