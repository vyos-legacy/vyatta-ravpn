#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use VyattaPPTPConfig;

my $FILE_CHAP_SECRETS = '/etc/ppp/chap-secrets';
my $FILE_PPP_OPTS = '/etc/ppp/options.pptpd';
my $FILE_PPTP_OPTS = '/etc/pptpd.conf';
my $PPTP_INIT = '/etc/init.d/pptpd';

my $config = new VyattaPPTPConfig;
my $oconfig = new VyattaPPTPConfig;
$config->setup();
$oconfig->setupOrig();

if ($config->isEmpty()) {
  if (!$oconfig->isEmpty()) {
    # deleted => stop
    system("$PPTP_INIT stop");
  }
  exit 0;
}

my ($chap_secrets, $ppp_opts, $pptp_conf, $err) = (undef, undef, undef, undef);
while (1) {
  ($chap_secrets, $err) = $config->get_chap_secrets();
  last if (defined($err));
  ($ppp_opts, $err) = $config->get_ppp_opts();
  last if (defined($err));
  ($pptp_conf, $err) = $config->get_pptp_conf($FILE_PPP_OPTS);
  last;
}
if (defined($err)) {
  print STDERR "PPTP VPN configuration error: $err.\n";
  exit 1;
}

exit 1 if (!$config->removeCfg($FILE_CHAP_SECRETS));
exit 1 if (!$config->removeCfg($FILE_PPP_OPTS));
exit 1 if (!$config->removeCfg($FILE_PPTP_OPTS));

exit 1 if (!$config->writeCfg($FILE_CHAP_SECRETS, $chap_secrets, 1, 0));
exit 1 if (!$config->writeCfg($FILE_PPP_OPTS, $ppp_opts, 0, 0));
exit 1 if (!$config->writeCfg($FILE_PPTP_OPTS, $pptp_conf, 0, 0));

# restart pptp
system("$PPTP_INIT restart");
exit 0;

