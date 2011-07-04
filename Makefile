/usr/bin/passwords: passwords.py
	cp passwords.py /usr/bin/passwords

install: /usr/bin/passwords

uninstall:
	rm /usr/bin/passwords