CREATE DATABASE traffic_monitoring;

USE traffic_monitoring;

-- Location Table
CREATE TABLE Location (
    Location_ID INT AUTO_INCREMENT PRIMARY KEY,
    Country VARCHAR(100),
    City VARCHAR(100),
    Region VARCHAR(100)
);

-- IP Traffic Table
CREATE TABLE IP_Traffic (
    IP_Address VARCHAR(45) PRIMARY KEY,
    Protocol_Type VARCHAR(10),
    User_Agent VARCHAR(255),
    Location_Location_ID INT,
    FOREIGN KEY (Location_Location_ID) REFERENCES Location(Location_ID)
);

-- Flagged Metrics Table
CREATE TABLE Flagged_Metrics (
    Metric_ID INT AUTO_INCREMENT PRIMARY KEY,
    Connection_Frequency VARCHAR(45),
    Failed_Login_Attempts INT,
    Data_Transfer_Volume BIGINT,
    Time_of_Activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    IP_Traffic_IP_Address VARCHAR(45),
    FOREIGN KEY (IP_Traffic_IP_Address) REFERENCES IP_Traffic(IP_Address)
);