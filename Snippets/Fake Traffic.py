import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor

# List of fake user-agents to simulate different browsers/devices
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0"
]

# Simulate user visiting different pages on the site
URLS = [
    "https://example.com",            # Home page
    "https://example.com/products",   # Products page
    "https://example.com/about",      # About page
    "https://example.com/contact",    # Contact page
    "https://example.com/blog",       # Blog page
]

# Function to simulate traffic (user visit)
def simulate_traffic(url):
    headers = {
        "User-Agent": random.choice(USER_AGENTS)  # Randomly select a user-agent
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(f"Successfully visited {url}")
        else:
            print(f"Failed to visit {url} - Status Code: {response.status_code}")
    except Exception as e:
        print(f"Error visiting {url}: {e}")

# Function to simulate multiple users (concurrent visits)
def generate_traffic():
    with ThreadPoolExecutor(max_workers=10) as executor:  # Maximum 10 concurrent threads
        while True:
            # Randomly select a page from the URL list
            url = random.choice(URLS)
            executor.submit(simulate_traffic, url)  # Submit the traffic simulation to the executor
            time.sleep(random.uniform(0.5, 2))  # Random delay between requests (0.5 to 2 seconds)

# Start the traffic generation
if __name__ == "__main__":
    print("Simulating traffic on the website...")
    generate_traffic()
