package VyattaPPTPConfig;

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use NetAddr::IP;

my $cfg_delim_begin = '### Vyatta PPTP VPN Begin ###';
my $cfg_delim_end = '### Vyatta PPTP VPN End ###';

my %fields = (
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

  $config->setLevel('vpn pptp remote-access');
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

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

  $config->setLevel('vpn pptp remote-access');
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

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

sub get_chap_secrets {
  my ($self) = @_;
  my @users = @{$self->{_auth_local}};
  return (undef, "Local user authentication not defined")
    if (scalar(@users) == 0);
  my $str = $cfg_delim_begin;
  while (scalar(@users) > 0) {
    my $user = shift @users;
    my $pass = shift @users;
    $str .= ("\n$user\t" . 'pptpd' . "\t\"$pass\"\t" . '*');
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
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
${sstr}debug
proxyarp
lock
nobsdcomp
novj
novjccomp
nologfd
$cfg_delim_end
EOS
  return ($str, undef);
}

sub get_ip_str {
  my ($start, $stop) = @_;
  my $ip1 = new NetAddr::IP "$start/24";
  my $ip2 = new NetAddr::IP "$stop/24";
  if ($ip1->network() != $ip2->network()) {
    return (undef, 'Client IP pool not within a /24');
  }
  if ($ip1 >= $ip2) {
    return (undef, 'Stop IP must be higher than start IP');
  }

  my $l2tp = new VyattaConfig;
  my $l1 = $l2tp->returnValue('vpn l2tp remote-access client-ip-pool start');
  my $l2 = $l2tp->returnValue('vpn l2tp remote-access client-ip-pool stop');
  if (defined($l1) && defined($l2)) {
    my $ipl1 = new NetAddr::IP "$l1/32";
    my $ipl2 = new NetAddr::IP "$l2/32";
    return (undef, 'L2TP and PPTP client IP pools overlap')
      if (!(($ip1 > $ipl2) || ($ip2 < $ipl1)));
  }

  $stop =~ m/\.(\d+)$/;
  return ("$start-$1", undef);
}

sub get_pptp_conf {
  my ($self, $ppp_opts) = @_;
  my $cstart = $self->{_client_ip_start};
  return (undef, "Client IP pool start not defined") if (!defined($cstart));
  my $cstop = $self->{_client_ip_stop};
  return (undef, "Client IP pool stop not defined") if (!defined($cstop));
  my ($ip_str, $err) = get_ip_str($cstart, $cstop);
  return (undef, "$err") if (!defined($ip_str));
  
  my $str =<<EOS;
$cfg_delim_begin
option $ppp_opts
debug
logwtmp
localip 10.255.254.0
remoteip $ip_str
$cfg_delim_end
EOS
  return ($str, undef);
}

sub removeCfg {
  my ($self, $file) = @_;
  system("sed -i '/$cfg_delim_begin/,/$cfg_delim_end/d' $file");
  if ($? >> 8) {
    print STDERR <<EOM;
PPTP VPN configuration error: Cannot remove old config from $file.
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
PPTP VPN configuration error: Cannot write config to $file.
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
  my $str = 'pptp vpn';
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

