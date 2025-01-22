import hashlib
import os
import hmac

class Hashing:

    @staticmethod
    def __generate_salt() -> bytes:
        salt = os.urandom(32)
        return salt
    
    @staticmethod
    def __compute_hash(data: str, salt: bytes) -> bytes:

        secure_data = data.encode("utf-8") + salt
        return hashlib.sha256(secure_data).hexdigest()
    
    def create_hash(self, data: str) -> tuple[str, str]:
        salt = self.__generate_salt()
        hashed_data = self.__compute_hash(data, salt)
        return hashed_data, salt
    
    def compare_hash(self, data: str, stored_hash: bytes, stored_salt: bytes) -> bool:
        try:
            re_hash = self.__compute_hash(data, stored_salt)
            return hmac.compare_digest(re_hash, stored_hash)

        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid hash or salt: {str(e)}")
        
hasher = Hashing()

### Example of usage 

# Suspicious IP that needs to be stored
IP = "192.168.10.1"

# Hashing the IP for storage
IP_Hashed, Stored_Salt = hasher.create_hash(IP)
print(IP_Hashed)
# Returns the hashed IP
print(Stored_Salt)
# Returns the salt generated for that IP 

# Comparing generic IP to suspicious IP
Good_IP = "192.168.30.3"
print(hasher.compare_hash(Good_IP, IP_Hashed, Stored_Salt))
# Returns false because they aren't the same