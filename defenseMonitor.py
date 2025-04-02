from defense.defenseScript import Blocker
from database import databaseScript
import logging

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class RunDefense: 
    def __init__(self, db, block_duration=300):
        '''
        Initalises the RunDefense class, the class that conjoins the database script with the defense script
        Args:
            db: Database instance from databaseScript.py
            block_duration: Duration in seconds that the blocker script needs to block each IP
        '''

        self.db = db
        self.blocker = Blocker(block_duration=block_duration)
        logging.info("RunDefense Class Initalised")

    def block_ip():
        pass

    def unblock_ip():
        pass

    def add_rate_limit():
        pass

    def remove_rate_limit():
        pass