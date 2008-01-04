package VyattaL2TPConfig;

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use NetAddr::IP;

my $cfg_delim_begin = '### Vyatta L2TP VPN Begin ###';
my $cfg_delim_end = '### Vyatta L2TP VPN End ###';

my $CA_CERT_PATH = '/etc/ipsec.d/cacerts';
my $CRL_PATH = '/etc/ipsec.d/crls';
my $SERVER_CERT_PATH = '/etc/ipsec.d/certs';
my $SERVER_KEY_PATH = '/etc/ipsec.d/private';

my %fields = (
  _mode             => undef,
  _psk              => undef,
  _x509_cacert      => undef,
  _x509_crl         => undef,
  _x509_s_cert      => undef,
  _x509_s_key       => undef,
  _x509_s_pass      => undef,
  _out_addr         => undef,
  _out_nexthop      => undef,
  _client_ip_start  => undef,
  _client_ip_stop   => undef,
  _auth_local       => [],
  _dns              => [],
  _wins             => [],
  _is_empty         => 1,
);

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setup {
  my ( $self ) = @_;
  my $config = new VyattaConfig;

  $config->setLevel('vpn l2tp remote-access');
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_mode} = $config->returnValue('ipsec-settings authentication mode');
  $self->{_psk}
    = $config->returnValue('ipsec-settings authentication pre-shared-secret');
  my $pfx = 'ipsec-settings authentication x509';
  $self->{_x509_cacert} = $config->returnValue("$pfx ca-cert-file");
  $self->{_x509_crl} = $config->returnValue("$pfx crl-file");
  $self->{_x509_s_cert} = $config->returnValue("$pfx server-cert-file");
  $self->{_x509_s_key} = $config->returnValue("$pfx server-key-file");
  $self->{_x509_s_pass} = $config->returnValue("$pfx server-key-password");

  $self->{_out_addr} = $config->returnValue('outside-address');
  $self->{_out_nexthop} = $config->returnValue('outside-nexthop');
  $self->{_client_ip_start} = $config->returnValue('client-ip-pool start');
  $self->{_client_ip_stop} = $config->returnValue('client-ip-pool stop');

  my @users = $config->listNodes('authentication local-users username');
  foreach my $user (@users) {
    my $plvl = "authentication local-users username $user password";
    my $pass = $config->returnValue("$plvl");
    $self->{_auth_local} = [ @{$self->{_auth_local}}, $user, $pass ];
  }

  my $tmp = $config->returnValue('dns-servers server-1');
  if (defined($tmp)) {
    $self->{_dns} = [ @{$self->{_dns}}, $tmp ];
  }
  $tmp = $config->returnValue('dns-servers server-2');
  if (defined($tmp)) {
    $self->{_dns} = [ @{$self->{_dns}}, $tmp ];
  }
  
  $tmp = $config->returnValue('wins-servers server-1');
  if (defined($tmp)) {
    $self->{_wins} = [ @{$self->{_wins}}, $tmp ];
  }
  $tmp = $config->returnValue('wins-servers server-2');
  if (defined($tmp)) {
    $self->{_wins} = [ @{$self->{_wins}}, $tmp ];
  }

  return 0;
}

sub setupOrig {
  my ( $self ) = @_;
  my $config = new VyattaConfig;

  $config->setLevel('vpn l2tp remote-access');
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_mode} = $config->returnOrigValue(
                            'ipsec-settings authentication mode');
  $self->{_psk} = $config->returnOrigValue(
                            'ipsec-settings authentication pre-shared-secret');
  my $pfx = 'ipsec-settings authentication x509';
  $self->{_x509_cacert} = $config->returnOrigValue("$pfx ca-cert-file");
  $self->{_x509_crl} = $config->returnOrigValue("$pfx crl-file");
  $self->{_x509_s_cert} = $config->returnOrigValue("$pfx server-cert-file");
  $self->{_x509_s_key} = $config->returnOrigValue("$pfx server-key-file");
  $self->{_x509_s_pass} = $config->returnOrigValue("$pfx server-key-password");

  $self->{_out_addr} = $config->returnOrigValue('outside-address');
  $self->{_out_nexthop} = $config->returnOrigValue('outside-nexthop');
  $self->{_client_ip_start} = $config->returnOrigValue('client-ip-pool start');
  $self->{_client_ip_stop} = $config->returnOrigValue('client-ip-pool stop');

  my @users = $config->listOrigNodes('authentication local-users username');
  foreach my $user (@users) {
    my $plvl = "authentication local-users username $user password";
    my $pass = $config->returnOrigValue("$plvl");
    $self->{_auth_local} = [ @{$self->{_auth_local}}, $user, $pass ];
  }

  my $tmp = $config->returnOrigValue('dns-servers server-1');
  if (defined($tmp)) {
    $self->{_dns} = [ @{$self->{_dns}}, $tmp ];
  }
  $tmp = $config->returnOrigValue('dns-servers server-2');
  if (defined($tmp)) {
    $self->{_dns} = [ @{$self->{_dns}}, $tmp ];
  }
  
  $tmp = $config->returnOrigValue('wins-servers server-1');
  if (defined($tmp)) {
    $self->{_wins} = [ @{$self->{_wins}}, $tmp ];
  }
  $tmp = $config->returnOrigValue('wins-servers server-2');
  if (defined($tmp)) {
    $self->{_wins} = [ @{$self->{_wins}}, $tmp ];
  }

  return 0;
}

sub listsDiff {
  my @a = @{$_[0]};
  my @b = @{$_[1]};
  return 1 if ((scalar @a) != (scalar @b));
  while (my $a = shift @a) {
    my $b = shift @b;
    return 1 if ($a ne $b);
  }
  return 0;
}

sub isDifferentFrom {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_mode} ne $that->{_mode});
  return 1 if ($this->{_psk} ne $that->{_psk});
  return 1 if ($this->{_x509_cacert} ne $that->{_x509_cacert});
  return 1 if ($this->{_x509_crl} ne $that->{_x509_crl});
  return 1 if ($this->{_x509_s_cert} ne $that->{_x509_s_cert});
  return 1 if ($this->{_x509_s_key} ne $that->{_x509_s_key});
  return 1 if ($this->{_x509_s_pass} ne $that->{_x509_s_pass});
  return 1 if ($this->{_out_addr} ne $that->{_out_addr});
  return 1 if ($this->{_out_nexthop} ne $that->{_out_nexthop});
  return 1 if ($this->{_client_ip_start} ne $that->{_client_ip_start});
  return 1 if ($this->{_client_ip_stop} ne $that->{_client_ip_stop});
  return 1 if (listsDiff($this->{_auth_local}, $that->{_auth_local}));
  return 1 if (listsDiff($this->{_dns}, $that->{_dns}));
  return 1 if (listsDiff($this->{_wins}, $that->{_wins}));
  
  return 0;
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

sub setupX509IfNecessary {
  my ($self) = @_;
  my $mode = $self->{_mode};
  if ($mode eq 'pre-shared-secret') {
    return undef;
  }

  return "\"$self->{_x509_cacert}\" does not exist"
    if (! -f $self->{_x509_cacert});
  return "\"$self->{_x509_crl}\" does not exist"
    if (! -f $self->{_x509_crl});
  return "\"$self->{_x509_s_cert}\" does not exist"
    if (! -f $self->{_x509_s_cert});
  return "\"$self->{_x509_s_key}\" does not exist"
    if (! -f $self->{_x509_s_key});

  # perform more validation of the files

  system("cp -f $self->{_x509_cacert} $CA_CERT_PATH/");
  return "Cannot copy $self->{_x509_cacert}" if ($? >> 8);
  system("cp -f $self->{_x509_crl} $CRL_PATH/");
  return "Cannot copy $self->{_x509_crl}" if ($? >> 8);
  system("cp -f $self->{_x509_s_cert} $SERVER_CERT_PATH/");
  return "Cannot copy $self->{_x509_s_cert}" if ($? >> 8);
  system("cp -f $self->{_x509_s_key} $SERVER_KEY_PATH/");
  return "Cannot copy $self->{_x509_s_key}" if ($? >> 8);

  return undef;
}

sub get_ipsec_secrets {
  my ($self) = @_;
  my $mode = $self->{_mode};
  if ($mode eq 'pre-shared-secret') {
    # PSK
    my $key = $self->{_psk};
    my $oaddr = $self->{_out_addr};
    return (undef, "IPSec pre-shared secret not defined") if (!defined($key));
    return (undef, "Outside address not defined") if (!defined($oaddr));
    my $str =<<EOS;
$cfg_delim_begin
$oaddr %any : PSK "$key"
$cfg_delim_end
EOS
    return ($str, undef);
  } else {
    # X509
    my $key_file = $self->{_x509_s_key};
    my $key_pass = $self->{_x509_s_pass};
    return (undef, "\"server-key-file\" not defined")
      if (!defined($key_file));
    return (undef, "\"server-key-password\" not defined")
      if (!defined($key_pass));
    $key_file =~ s/^.*(\/[^\/]+)$/${SERVER_KEY_PATH}$1/;
    my $str =<<EOS;
$cfg_delim_begin
: RSA $key_file "$key_pass"
$cfg_delim_end
EOS
    return ($str, undef);
  }
}

sub get_ra_conn {
  my ($self, $name) = @_;
  my $oaddr = $self->{_out_addr};
  return (undef, "Outside address not defined") if (!defined($oaddr));
  my $onh = $self->{_out_nexthop};
  return (undef, "Outside nexthop not defined") if (!defined($onh));
  my $auth_str = "  authby=secret\n";
  if ($self->{_mode} eq 'x509') {
    my $server_cert = $self->{_x509_s_cert};
    return (undef, "\"server-cert-file\" not defined")
      if (!defined($server_cert));
    $server_cert =~ s/^.*(\/[^\/]+)$/${SERVER_CERT_PATH}$1/;
    $auth_str =<<EOS
  authby=rsasig
  leftrsasigkey=%cert
  rightrsasigkey=%cert
  leftcert=$server_cert
EOS
  }
  my $str =<<EOS;
$cfg_delim_begin
conn $name
${auth_str}  pfs=no
  left=$oaddr
  leftprotoport=17/1701
  leftnexthop=$onh
  right=%any
  rightprotoport=17/1701
  rightsubnet=vhost:%no,%priv
  auto=add
  ike="aes256-sha1,3des-sha1"
  ikelifetime=3600s
  dpddelay=15
  dpdtimeout=45
  dpdaction=clear
  esp="aes256-sha1,3des-sha1"
  rekey=no
$cfg_delim_end
EOS
  return ($str, undef);
}

sub get_chap_secrets {
  my ($self) = @_;
  my @users = @{$self->{_auth_local}};
  return (undef, "Local user authentication not defined")
    if (scalar(@users) == 0);
  my $str = $cfg_delim_begin;
  while (scalar(@users) > 0) {
    my $user = shift @users;
    my $pass = shift @users;
    $str .= ("\n$user\t" . 'xl2tpd' . "\t\"$pass\"\t" . '*');
  }
  $str .= "\n$cfg_delim_end\n";
  return ($str, undef);
}

sub get_ppp_opts {
  my ($self) = @_;
  my @dns = @{$self->{_dns}};
  my @wins = @{$self->{_wins}};
  my $sstr = '';
  foreach my $d (@dns) {
    $sstr .= ('ms-dns ' . "$d\n");
  }
  foreach my $w (@wins) {
    $sstr .= ('ms-wins ' . "$w\n");
  }
  my $str =<<EOS;
$cfg_delim_begin
name xl2tpd
ipcp-accept-local
ipcp-accept-remote
${sstr}noccp
auth
crtscts
idle 1800
mtu 1400
mru 1400
nodefaultroute
debug
lock
proxyarp
connect-delay 5000
$cfg_delim_end
EOS
  return ($str, undef);
}

sub get_l2tp_conf {
  my ($self, $ppp_opts) = @_;
  my $oaddr = $self->{_out_addr};
  return (undef, 'Outside address not defined') if (!defined($oaddr));
  my $cstart = $self->{_client_ip_start};
  return (undef, 'Client IP pool start not defined') if (!defined($cstart));
  my $cstop = $self->{_client_ip_stop};
  return (undef, 'Client IP pool stop not defined') if (!defined($cstop));
  my $ip1 = new NetAddr::IP "$cstart/32";
  my $ip2 = new NetAddr::IP "$cstop/32";
  return (undef, 'Stop IP must be higher than start IP') if ($ip1 >= $ip2);

  my $pptp = new VyattaConfig;
  my $p1 = $pptp->returnValue('vpn pptp remote-access client-ip-pool start');
  my $p2 = $pptp->returnValue('vpn pptp remote-access client-ip-pool stop');
  if (defined($p1) && defined($p2)) {
    my $ipp1 = new NetAddr::IP "$p1/32";
    my $ipp2 = new NetAddr::IP "$p2/32";
    return (undef, 'L2TP and PPTP client IP pools overlap')
      if (!(($ip1 > $ipp2) || ($ip2 < $ipp1)));
  }

  my $str =<<EOS;
;$cfg_delim_begin
[global]
listen-addr = $oaddr

[lns default]
ip range = $cstart-$cstop
local ip = 10.255.255.0
require chap = yes
refuse pap = yes
require authentication = yes
name = VyattaL2TPServer 
ppp debug = yes
pppoptfile = $ppp_opts
length bit = yes
;$cfg_delim_end
EOS
  return ($str, undef);
}

sub removeCfg {
  my ($self, $file) = @_;
  system("sed -i '/$cfg_delim_begin/,/$cfg_delim_end/d' $file");
  if ($? >> 8) {
    print STDERR <<EOM;
L2TP VPN configuration error: Cannot remove old config from $file.
EOM
    return 0;
  }
  return 1;
}

sub writeCfg {
  my ($self, $file, $cfg, $append, $delim) = @_;
  my $op = ($append) ? '>>' : '>';
  if (!open(WR, "$op$file")) {
    print STDERR <<EOM;
L2TP VPN configuration error: Cannot write config to $file.
EOM
    return 0;
  }
  if ($delim) {
    $cfg = "$cfg_delim_begin\n" . $cfg . "\n$cfg_delim_end\n";
  }
  print WR "$cfg";
  close WR;
  return 1;
}

sub print_str {
  my ($self) = @_;
  my $str = 'l2tp vpn';
  $str .= "\n  psk " . $self->{_psk};
  $str .= "\n  oaddr " . $self->{_out_addr};
  $str .= "\n  onexthop " . $self->{_out_nexthop};
  $str .= "\n  cip_start " . $self->{_client_ip_start};
  $str .= "\n  cip_stop " . $self->{_client_ip_stop};
  $str .= "\n  auth_local " . (join ",", @{$self->{_auth_local}});
  $str .= "\n  dns " . (join ",", @{$self->{_dns}});
  $str .= "\n  wins " . (join ",", @{$self->{_wins}});
  $str .= "\n  empty " . $self->{_is_empty};
  $str .= "\n";

  return $str;
}

1;

