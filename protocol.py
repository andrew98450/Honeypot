from enum import Enum
class Protocol(Enum):
    FTP = 21
    TELNET = 23
    DNS = 53
    HTTP = 80
    HTTPS = 443
    SMB = 445
    MSSQL = 1433
    MYSQL = 3306