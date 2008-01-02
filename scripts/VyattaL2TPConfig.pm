package VyattaL2TPConfig;

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;

my $cfg_delim_begin = '### Vyatta L2TP VPN Begin ###';
my $cfg_delim_end = '### Vyatta L2TP VPN End ###';

my %fields = (
  _psk              => undef,
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

  $self->{_psk} = $config->returnValue('ipsec-settings pre-shared-secret');
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

  $self->{_psk} = $config->returnOrigValue('ipsec-settings pre-shared-secret');
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
  
  return 1 if ($this->{_is_empty} != $that->{_is_empty});
  return 1 if ($this->{_psk} != $that->{_psk});
  return 1 if ($this->{_out_addr} != $that->{_out_addr});
  return 1 if ($this->{_out_nexthop} != $that->{_out_nexthop});
  return 1 if ($this->{_client_ip_start} != $that->{_client_ip_start});
  return 1 if ($this->{_client_ip_stop} != $that->{_client_ip_stop});
  return 1 if (listsDiff($this->{_auth_local}, $that->{_auth_local}));
  return 1 if (listsDiff($this->{_dns}, $that->{_dns}));
  return 1 if (listsDiff($this->{_wins}, $that->{_wins}));
  
  return 0;
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

sub get_ipsec_secrets {
  my ($self) = @_;
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
}

sub get_ra_conn {
  my ($self, $name) = @_;
  my $oaddr = $self->{_out_addr};
  return (undef, "Outside address not defined") if (!defined($oaddr));
  my $onh = $self->{_out_nexthop};
  return (undef, "Outside nexthop not defined") if (!defined($onh));
  my $str =<<EOS;
$cfg_delim_begin
conn $name
  authby=secret
  pfs=no
  left=$oaddr
  leftprotoport=17/1701
  leftnexthop=$onh
  right=%any
  rightprotoport=17/1701
  rightsubnet=vhost:%no,%priv
  auto=add
  ike="3des-sha1,aes256-sha1"
  ikelifetime=3600s
  dpddelay=15
  dpdtimeout=45
  dpdaction=clear
  esp="3des-sha1,aes256-sha1"
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
  return (undef, "Outside address not defined") if (!defined($oaddr));
  my $cstart = $self->{_client_ip_start};
  return (undef, "Client IP pool start not defined") if (!defined($cstart));
  my $cstop = $self->{_client_ip_stop};
  return (undef, "Client IP pool stop not defined") if (!defined($cstop));
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
Remote access VPN configuration error: Cannot remove old config from $file.
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
Remote access VPN configuration error: Cannot write config to $file.
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

