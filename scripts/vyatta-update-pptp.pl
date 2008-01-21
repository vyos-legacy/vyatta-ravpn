#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use VyattaPPTPConfig;

my $FILE_CHAP_SECRETS = '/etc/ppp/secrets/chap-ravpn';
my $FILE_PPP_OPTS = '/etc/ppp/options.pptpd';
my $FILE_PPTP_OPTS = '/etc/pptpd.conf';
my $PPTP_INIT = '/etc/init.d/pptpd';
my $FILE_RADIUS_CONF = '/etc/radiusclient-ng/radiusclient-pptp.conf';
my $FILE_RADIUS_KEYS = '/etc/radiusclient-ng/servers-pptp';

my $config = new VyattaPPTPConfig;
my $oconfig = new VyattaPPTPConfig;
$config->setup();
$oconfig->setupOrig();

if (!($config->isDifferentFrom($oconfig))) {
  # config not changed. do nothing.
  exit 0;
}

if ($config->isEmpty()) {
  if (!$oconfig->isEmpty()) {
    # deleted => stop
    system("kill -TERM `pgrep -f 'pppd.* /etc/ppp/options\\.pptpd'` "
           . '>&/dev/null');
    system("$PPTP_INIT stop");
  }
  exit 0;
}

my ($chap_secrets, $ppp_opts, $pptp_conf, $radius_conf, $radius_keys, $err)
  = (undef, undef, undef, undef, undef, undef);
while (1) {
  ($chap_secrets, $err) = $config->get_chap_secrets();
  last if (defined($err));
  ($ppp_opts, $err) = $config->get_ppp_opts();
  last if (defined($err));
  ($pptp_conf, $err) = $config->get_pptp_conf($FILE_PPP_OPTS);
  last if (defined($err));
  ($radius_conf, $err) = $config->get_radius_conf();
  last if (defined($err));
  ($radius_keys, $err) = $config->get_radius_keys();
  last;
}
if (defined($err)) {
  print STDERR "PPTP VPN configuration error: $err.\n";
  exit 1;
}

exit 1 if (!$config->removeCfg($FILE_CHAP_SECRETS));
exit 1 if (!$config->removeCfg($FILE_PPP_OPTS));
exit 1 if (!$config->removeCfg($FILE_PPTP_OPTS));
exit 1 if (!$config->removeCfg($FILE_RADIUS_CONF));
exit 1 if (!$config->removeCfg($FILE_RADIUS_KEYS));

exit 1 if (!$config->writeCfg($FILE_CHAP_SECRETS, $chap_secrets, 1, 0));
exit 1 if (!$config->writeCfg($FILE_PPP_OPTS, $ppp_opts, 0, 0));
exit 1 if (!$config->writeCfg($FILE_PPTP_OPTS, $pptp_conf, 0, 0));
exit 1 if (!$config->writeCfg($FILE_RADIUS_CONF, $radius_conf, 0, 0));
exit 1 if (!$config->writeCfg($FILE_RADIUS_KEYS, $radius_keys, 0, 0));

system('cat /etc/ppp/secrets/chap-* > /etc/ppp/chap-secrets');
if ($? >> 8) {
  print STDERR <<EOM;
PPTP VPN configuration error: Cannot write chap-secrets.
EOM
  exit 1;
}

if ($config->needsRestart($oconfig)) {
  # restart pptp
  # XXX need to kill all pptpd instances since it does not keep track of
  # existing sessions and will start assigning IPs already in use.
  system("kill -TERM `pgrep -f 'pppd.* /etc/ppp/options\\.pptpd'` "
         . '>&/dev/null');
  system("$PPTP_INIT restart");
}
exit 0;

