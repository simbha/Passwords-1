INSTALL_TARGET = /usr/bin/passwords

$(INSTALL_TARGET): passwords.py
	cp passwords.py $(INSTALL_TARGET)

install: $(INSTALL_TARGET)

uninstall:
	test -e $(INSTALL_TARGET) && rm $(INSTALL_TARGET)