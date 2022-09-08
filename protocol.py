from enum import Enum
class Protocol(Enum):
    FTP = 21
    SSH = 22
    TELNET = 23
    SMTP = 25
    DNS = 53
    HTTP = 80
    RPCBIND = 111
    NETBIOS = 139
    SMB = 445
    EXEC = 512
    LOGIN = 513
    SHELL = 514
    CCPROXY = 2121 
    MYSQL = 3306
    POSTGRESQL = 5432
    VNC = 5900
    X11 = 6000