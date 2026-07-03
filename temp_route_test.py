import os, sys
sys.path.insert(0, os.getcwd())
from app import app

with app.test_client() as client:
    login = client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    print('login status', login.status_code)
    print('login contains dashboard', 'Dashboard' in login.get_data(as_text=True))
    for path, data in [('/network', {'network': '127.0.0.1/32'}), ('/port', {'host': '127.0.0.1'}), ('/logs', {'logfile': 'sample.log'}), ('/integrity', {'filename': __file__})]:
        if path in ['/logs', '/integrity']:
            get_resp = client.get(path)
            print(path, get_resp.status_code, '<form>' in get_resp.get_data(as_text=True))
        post_resp = client.post(path, data=data, follow_redirects=True)
        print(path, 'POST', post_resp.status_code)
        body = post_resp.get_data(as_text=True)
        print('snippet', body[:300])
        print('contains error', 'danger' in body or 'Invalid' in body or 'Error' in body)
