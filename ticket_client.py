"""Persist ONE ticket across failover, unlike the login/logout Part 1 demo client."""
import argparse
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def post(url, path, payload):
    request = Request(url + path, data=json.dumps(payload).encode('utf-8'),
                      headers={'Content-Type': 'application/json'}, method='POST')
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, json.load(response)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['login', 'validate', 'logout'])
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    parser.add_argument('--ticket-file', type=Path, default=Path('demo_ticket.json'))
    args = parser.parse_args()
    try:
        if args.action == 'login':
            status, body = post(args.url, '/login',
                                {'username': 'alice', 'password': 'alice-demo'})
            if status == 200:
                args.ticket_file.write_text(json.dumps({'ticket': body['ticket']}))
                print('Saved ticket for validation after failover:', args.ticket_file)
                # Avoid displaying bearer tokens in terminal logs.
                body = {'ticket': '[saved to file]', 'expires_in_seconds': body['expires_in_seconds']}
        else:
            ticket = json.loads(args.ticket_file.read_text())['ticket']
            status, body = post(args.url, '/' + args.action, {'ticket': ticket})
        print(args.action, status, body)
        raise SystemExit(0 if status == 200 else 1)
    except (OSError, URLError, ValueError, KeyError) as exc:
        parser.exit(1, str(exc) + '\n')
