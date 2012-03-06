#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::L2TPConfig;

my $RACONN_NAME = 'remote-access';
## XXX only the part after the last '-' affects order of conn matching!!!?
my $RACONN_NAME_WIN = "${RACONN_NAME}-win-aaa";
my $RACONN_NAME_MAC = "${RACONN_NAME}-mac-zzz";
my $FILE_IPSEC_CFG = '/etc/ipsec.conf';
my $FILE_IPSEC_SECRETS = '/etc/ipsec.secrets';
my $FILE_IPSEC_RACONN = "/etc/ipsec.d/tunnels/$RACONN_NAME";
my $FILE_CHAP_SECRETS = '/etc/ppp/secrets/chap-ravpn';
my $FILE_PPP_OPTS = '/etc/ppp/options.xl2tpd';
my $FILE_L2TP_OPTS = '/etc/xl2tpd/xl2tpd.conf';
my $IPSEC_CTL_FILE = '/var/run/pluto.ctl';
my $FILE_RADIUS_CONF = '/etc/radiusclient-ng/radiusclient-l2tp.conf';
my $FILE_RADIUS_KEYS = '/etc/radiusclient-ng/servers-l2tp';
my $FILE_DHCP_HOOK = '/etc/dhcp3/dhclient-exit-hooks.d/l2tpd';

my $gconfig = new Vyatta::Config;
my $config = new Vyatta::L2TPConfig;
my $oconfig = new Vyatta::L2TPConfig;
my $err = $config->setup();
if (defined($err) && $err ne 0) {
  print STDERR "L2TP VPN configuration error: $err.\n";
  exit 1;
}
$oconfig->setupOrig();

if ($config->isEmpty()) {
  if (!$oconfig->isEmpty()) {
    # deleted
    # clear the dhclient hook
    system("echo '' > $FILE_DHCP_HOOK");
    # kill existing PPP sessions
    system("kill -TERM `pgrep -f 'name VyattaL2TPServer'` >&/dev/null");
    # stop L2TP server
    system("/etc/init.d/xl2tpd stop >&/dev/null");
    # remove remote-access vpn connections
    system ("ipsec rereadall >&/dev/null");
    system ("ipsec update >&/dev/null");
  }
  exit 0;
}

# required ipsec settings
## ipsec-interfaces
my @ipsec_ifs = $gconfig->returnValues('vpn ipsec ipsec-interfaces interface');
## nat-traversal
my $nat_traversal = $gconfig->returnValue('vpn ipsec nat-traversal');
## nat-networks
my @nat_nets = $gconfig->listNodes('vpn ipsec nat-networks allowed-network');

my ($dhcp_hook, $ipsec_secrets, $ra_conn, $chap_secrets, $ppp_opts, $l2tp_conf,
    $radius_conf, $radius_keys, $err)
  = (undef, undef, undef, undef, undef, undef, undef, undef, undef);
while (1) {
  if ((scalar @ipsec_ifs) <= 0) {
    $err = '"vpn ipsec ipsec-interfaces" must be specified';
    last;
  }
  if ($nat_traversal ne 'enable') {
    $err = '"vpn ipsec nat-traversal" must be enabled';
    last;
  }
  if ((scalar @nat_nets) <= 0) {
    $err = '"vpn ipsec nat-networks" must be specified';
    last;
  }
  ($dhcp_hook, $err) = $config->get_dhcp_hook();
  last if (defined($err));
  ($ipsec_secrets, $err) = $config->get_ipsec_secrets();
  last if (defined($err));
  ($ra_conn, $err) = $config->get_ra_conn($RACONN_NAME);
  last if (defined($err));
  ($chap_secrets, $err) = $config->get_chap_secrets();
  last if (defined($err));
  ($ppp_opts, $err) = $config->get_ppp_opts();
  last if (defined($err));
  ($l2tp_conf, $err) = $config->get_l2tp_conf($FILE_PPP_OPTS);
  last if (defined($err));
  ($radius_conf, $err) = $config->get_radius_conf();
  last if (defined($err));
  ($radius_keys, $err) = $config->get_radius_keys();
  last if (defined($err));
  $err = $config->setupX509IfNecessary();
  last;
}
if (defined($err)) {
  print STDERR "L2TP VPN configuration error: $err.\n";
  exit 1;
}
exit 1 if (!$config->removeCfg($FILE_DHCP_HOOK));
exit 1 if (!$config->removeCfg($FILE_IPSEC_CFG));
exit 1 if (!$config->removeCfg($FILE_IPSEC_SECRETS));
exit 1 if (!$config->removeCfg($FILE_IPSEC_RACONN));
exit 1 if (!$config->removeCfg($FILE_CHAP_SECRETS));
exit 1 if (!$config->removeCfg($FILE_PPP_OPTS));
exit 1 if (!$config->removeCfg($FILE_L2TP_OPTS));
exit 1 if (!$config->removeCfg($FILE_RADIUS_CONF));
exit 1 if (!$config->removeCfg($FILE_RADIUS_KEYS));

my $ipsec_cfg = "include $FILE_IPSEC_RACONN";
exit 1 if (!$config->writeCfg($FILE_DHCP_HOOK, $dhcp_hook, 0, 0));
exit 1 if (!$config->writeCfg($FILE_IPSEC_CFG, $ipsec_cfg, 1, 1));
exit 1 if (!$config->writeCfg($FILE_IPSEC_SECRETS, $ipsec_secrets, 1, 0));
exit 1 if (!$config->writeCfg($FILE_IPSEC_RACONN, $ra_conn, 0, 0));
exit 1 if (!$config->writeCfg($FILE_CHAP_SECRETS, $chap_secrets, 1, 0));
exit 1 if (!$config->writeCfg($FILE_PPP_OPTS, $ppp_opts, 0, 0));
exit 1 if (!$config->writeCfg($FILE_L2TP_OPTS, $l2tp_conf, 0, 0));
exit 1 if (!$config->writeCfg($FILE_RADIUS_CONF, $radius_conf, 0, 0));
exit 1 if (!$config->writeCfg($FILE_RADIUS_KEYS, $radius_keys, 0, 0));

system('cat /etc/ppp/secrets/chap-* > /etc/ppp/chap-secrets');
if ($? >> 8) {
  print STDERR <<EOM;
L2TP VPN configuration error: Cannot write chap-secrets.
EOM
  exit 1;
}

# wait for ipsec to settle
if (!($config->maybeClustering($gconfig, @ipsec_ifs))) {
  my $sleep = 0;
  while (! -e $IPSEC_CTL_FILE) {
    sleep 1;
    if (++$sleep > 10) {
      print STDERR "L2TP VPN configuration error: IPsec did not start.\n";
      exit 1;
    }
  }
}

# always need to rereadsecrets (until we can coordinate this with "ipsec").
# actually need rereadall since x509 settings may have been changed.
# only do this if we are not doing clustering.
if (!($config->maybeClustering($gconfig, @ipsec_ifs))) {
  system ("ipsec rereadall >&/dev/null");
  system ("ipsec update >&/dev/null");
}

if (!($config->isDifferentFrom($oconfig))) {
  # config not actually changed. do nothing.
  exit 0;
}

if (!($config->maybeClustering($gconfig, @ipsec_ifs))
    && $config->needsRestart($oconfig)) {
  # kill existing PPP sessions
  system("kill -TERM `pgrep -f 'name VyattaL2TPServer'` >&/dev/null");
  # update ipsec.conf for remote-access connections
  system ("ipsec rereadall >&/dev/null");
  system ("ipsec update >&/dev/null");
  # restart L2TP server
  system("/etc/init.d/xl2tpd stop >&/dev/null");
  system("/etc/init.d/xl2tpd start >&/dev/null");
}
exit 0;

