cfgdir		 = $(datadir)/vyatta-cfg/templates
opdir		 = $(datadir)/vyatta-op/templates
share_perl5dir	 = $(datarootdir)/perl5/Vyatta
ravpnconfdir = $(sysconfdir)/ravpn
bin_sudo_usersdir = $(bindir)/sudo-users

sbin_SCRIPTS = scripts/vyatta-update-l2tp.pl
sbin_SCRIPTS += scripts/vyatta-update-pptp.pl
sbin_SCRIPTS += scripts/vyatta-show-ravpn.pl

bin_sudo_users_SCRIPTS = scripts/vyatta-kick-ravpn.pl
bin_sudo_users_SCRIPTS += scripts/vyatta-pptp-dhcp.pl

share_perl5_DATA = lib/Vyatta/L2TPConfig.pm
share_perl5_DATA += lib/Vyatta/PPTPConfig.pm

ravpnconf_SCRIPTS = scripts/ppp-ip-up
ravpnconf_SCRIPTS += scripts/ppp-ip-down
ravpnconf_DATA = scripts/radius-dictionary.microsoft

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)
	mkdir -p $(DESTDIR)/etc/ppp/ip-pre-up.d \
	         $(DESTDIR)/etc/ppp/ip-up.d \
	         $(DESTDIR)/etc/ppp/ip-down.d
	cp scripts/rename-l2tp $(DESTDIR)/etc/ppp/ip-pre-up.d/0004rename-l2tp
	chmod 755 $(DESTDIR)/etc/ppp/ip-pre-up.d/0004rename-l2tp
	cp scripts/rename-pptp $(DESTDIR)/etc/ppp/ip-pre-up.d/0005rename-pptp
	chmod 755 $(DESTDIR)/etc/ppp/ip-pre-up.d/0005rename-pptp

