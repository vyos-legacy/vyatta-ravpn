cfgdir		 = $(datadir)/vyatta-cfg/templates
opdir		 = $(datadir)/vyatta-op/templates
share_perl5dir	 = $(datarootdir)/perl5/Vyatta
ravpnconfdir = $(sysconfdir)/ravpn
bin_sudo_usersdir = $(bindir)/sudo-users

sbin_SCRIPTS = scripts/vyatta-update-l2tp.pl
sbin_SCRIPTS += scripts/vyatta-update-pptp.pl
sbin_SCRIPTS += scripts/vyatta-show-ravpn.pl

bin_sudo_users_SCRIPTS = scripts/vyatta-kick-ravpn.pl

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

