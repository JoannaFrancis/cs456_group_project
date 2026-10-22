"""Run after critical_service.py to show login, validation, logout, rejection."""
import argparse
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def post(base, path, payload):
    request = Request(base + path, data=json.dumps(payload).encode(),
                      headers={'Content-Type': 'application/json'}, method='POST')
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as exc:
        response = exc
    with response:
        result = json.load(response)
        # Tickets are only printed here so the user can see the demo result.
        print(path, response.status, result)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    args = parser.parse_args()
    result = post(args.url, '/login', {'username': 'alice', 'password': 'alice-demo'})
    if 'ticket' in result:
        post(args.url, '/validate', {'ticket': result['ticket']})
        post(args.url, '/logout', {'ticket': result['ticket']})
        post(args.url, '/validate', {'ticket': result['ticket']})
    post(args.url, '/login', {'username': 'alice', 'password': 'wrong'})
