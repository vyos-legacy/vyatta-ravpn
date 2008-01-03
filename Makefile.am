cfgdir		 = $(datadir)/vyatta-cfg/templates
share_perl5dir	 = $(datarootdir)/perl5
ravpnconfdir = $(sysconfdir)/ravpn

sbin_SCRIPTS = scripts/vyatta-update-l2tp.pl
sbin_SCRIPTS += scripts/vyatta-update-pptp.pl

share_perl5_DATA = scripts/VyattaL2TPConfig.pm
share_perl5_DATA += scripts/VyattaPPTPConfig.pm

ravpnconf_SCRIPTS = scripts/ppp-auth-up
ravpnconf_SCRIPTS += scripts/ppp-auth-down

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)

