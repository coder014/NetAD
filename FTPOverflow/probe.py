import ftplib
from ftplib import FTP

if __name__ == '__main__':
	ftp = FTP()
	ftp.connect('127.0.0.1', 2121)
	probe_str = ''.join(['A{:03d}'.format(i) for i in range(151)])
	try:
		ftp.login(probe_str, 'aaa')
		ftp.close()
	except ftplib.all_errors:
		pass