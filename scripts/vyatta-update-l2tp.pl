#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use VyattaL2TPConfig;

my $RACONN_NAME = 'remote-access';
my $FILE_IPSEC_CFG = '/etc/ipsec.conf';
my $FILE_IPSEC_SECRETS = '/etc/ipsec.secrets';
my $FILE_IPSEC_RACONN = "/etc/ipsec.d/tunnels/$RACONN_NAME";
my $FILE_CHAP_SECRETS = '/etc/ppp/chap-secrets';
my $FILE_PPP_OPTS = '/etc/ppp/options.xl2tpd';
my $FILE_L2TP_OPTS = '/etc/xl2tpd/xl2tpd.conf';

my $config = new VyattaL2TPConfig;
my $oconfig = new VyattaL2TPConfig;
$config->setup();
$oconfig->setupOrig();

if ($config->isEmpty()) {
  if (!$oconfig->isEmpty()) {
    # deleted => remove ipsec conn
    system("/etc/init.d/xl2tpd stop");
    system("ipsec auto --delete $RACONN_NAME");
  }
  exit 0;
}

my ($ipsec_secrets, $ra_conn, $chap_secrets, $ppp_opts, $l2tp_conf, $err)
  = (undef, undef, undef, undef, undef, undef);
while (1) {
  ($ipsec_secrets, $err) = $config->get_ipsec_secrets();
  last if (defined($err));
  ($ra_conn, $err) = $config->get_ra_conn($RACONN_NAME);
  last if (defined($err));
  ($chap_secrets, $err) = $config->get_chap_secrets();
  last if (defined($err));
  ($ppp_opts, $err) = $config->get_ppp_opts();
  last if (defined($err));
  ($l2tp_conf, $err) = $config->get_l2tp_conf($FILE_PPP_OPTS);
  last;
}
if (defined($err)) {
  print STDERR "Remote access VPN configuration error: $err.\n";
  exit 1;
}

exit 1 if (!$config->removeCfg($FILE_IPSEC_CFG));
exit 1 if (!$config->removeCfg($FILE_IPSEC_SECRETS));
exit 1 if (!$config->removeCfg($FILE_IPSEC_RACONN));
exit 1 if (!$config->removeCfg($FILE_CHAP_SECRETS));
exit 1 if (!$config->removeCfg($FILE_PPP_OPTS));
exit 1 if (!$config->removeCfg($FILE_L2TP_OPTS));

my $ipsec_cfg = "include $FILE_IPSEC_RACONN";
exit 1 if (!$config->writeCfg($FILE_IPSEC_CFG, $ipsec_cfg, 1, 1));
exit 1 if (!$config->writeCfg($FILE_IPSEC_SECRETS, $ipsec_secrets, 1, 0));
exit 1 if (!$config->writeCfg($FILE_IPSEC_RACONN, $ra_conn, 0, 0));
exit 1 if (!$config->writeCfg($FILE_CHAP_SECRETS, $chap_secrets, 1, 0));
exit 1 if (!$config->writeCfg($FILE_PPP_OPTS, $ppp_opts, 0, 0));
exit 1 if (!$config->writeCfg($FILE_L2TP_OPTS, $l2tp_conf, 0, 0));

# add the ipsec connection
system("ipsec auto --delete $RACONN_NAME >&/dev/null");
system("ipsec auto --add $RACONN_NAME");
system("ipsec auto --rereadsecrets");
system("/etc/init.d/xl2tpd stop >&/dev/null");
system("/etc/init.d/xl2tpd start");
exit 0;

