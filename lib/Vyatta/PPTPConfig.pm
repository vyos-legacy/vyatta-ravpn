package Vyatta::PPTPConfig;

use strict;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::Misc;
use NetAddr::IP;

my $cfg_delim_begin = '### Vyatta PPTP VPN Begin ###';
my $cfg_delim_end = '### Vyatta PPTP VPN End ###';

my %fields = (
  _client_ip_start  => undef,
  _client_ip_stop   => undef,
  _out_addr         => undef,
  _dhcp_iface       => undef,
  _auth_mode        => undef,
  _mtu              => undef,
  _auth_local       => [],
  _auth_radius      => [],
  _auth_radius_keys => [],
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
  my $config = new Vyatta::Config;

  $config->setLevel('vpn pptp remote-access');
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_out_addr} = $config->returnValue('outside-address');
  $self->{_dhcp_iface} = $config->returnValue('dhcp-interface');
  $self->{_client_ip_start} = $config->returnValue('client-ip-pool start');
  $self->{_client_ip_stop} = $config->returnValue('client-ip-pool stop');
  $self->{_auth_mode} = $config->returnValue('authentication mode');
  $self->{_mtu} = $config->returnValue('mtu');

  my @users = $config->listNodes('authentication local-users username');
  foreach my $user (@users) {
    my $plvl = "authentication local-users username $user password";
    my $pass = $config->returnValue("$plvl");
    my $dlvl = "authentication local-users username $user disable";
    my $disable = 'enable';
    $disable = 'disable' if $config->exists("$dlvl");
    my $ilvl = "authentication local-users username $user static-ip";
    my $ip = $config->returnValue("$ilvl");
    $self->{_auth_local} = [ @{$self->{_auth_local}}, $user, $pass, $disable, $ip ];
  }
  
  my @rservers = $config->listNodes('authentication radius-server');
  foreach my $rserver (@rservers) {
    my $key = $config->returnValue(
                        "authentication radius-server $rserver key");
    $self->{_auth_radius} = [ @{$self->{_auth_radius}}, $rserver ];
    if (defined($key)) {
      $self->{_auth_radius_keys} = [ @{$self->{_auth_radius_keys}}, $key ];
    }
    # later we will check if the two lists have the same length
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
  my $config = new Vyatta::Config;

  $config->setLevel('vpn pptp remote-access');
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }

  $self->{_out_addr} = $config->returnOrigValue('outside-address');
  $self->{_dhcp_iface} = $config->returnOrigValue('dhcp-interface');
  $self->{_client_ip_start} = $config->returnOrigValue('client-ip-pool start');
  $self->{_client_ip_stop} = $config->returnOrigValue('client-ip-pool stop');
  $self->{_auth_mode} = $config->returnOrigValue('authentication mode');
  $self->{_mtu} = $config->returnOrigValue('mtu');

  my @users = $config->listOrigNodes('authentication local-users username');
  foreach my $user (@users) {
    my $plvl = "authentication local-users username $user password";
    my $pass = $config->returnOrigValue("$plvl");
    my $dlvl = "authentication local-users username $user disable";
    my $disable = 'enable';
    $disable = 'disable' if $config->existsOrig("$dlvl");
    my $ilvl = "authentication local-users username $user static-ip";
    my $ip = $config->returnOrigValue("$ilvl");
    $self->{_auth_local} = [ @{$self->{_auth_local}}, $user, $pass, $disable, $ip ];
  }
  
  my @rservers = $config->listOrigNodes('authentication radius-server');
  foreach my $rserver (@rservers) {
    my $key = $config->returnOrigValue(
                        "authentication radius-server $rserver key");
    $self->{_auth_radius} = [ @{$self->{_auth_radius}}, $rserver ];
    if (defined($key)) {
      $self->{_auth_radius_keys} = [ @{$self->{_auth_radius_keys}}, $key ];
    }
    # later we will check if the two lists have the same length
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
  return 1 if ($this->{_out_addr} ne $that->{_out_addr});
  return 1 if ($this->{_dhcp_iface} ne $that->{_dhcp_iface});
  return 1 if ($this->{_client_ip_start} ne $that->{_client_ip_start});
  return 1 if ($this->{_client_ip_stop} ne $that->{_client_ip_stop});
  return 1 if ($this->{_auth_mode} ne $that->{_auth_mode});
  return 1 if ($this->{_mtu} ne $that->{_mtu});
  return 1 if (listsDiff($this->{_auth_local}, $that->{_auth_local}));
  return 1 if (listsDiff($this->{_auth_radius}, $that->{_auth_radius}));
  return 1 if (listsDiff($this->{_auth_radius_keys},
                         $that->{_auth_radius_keys}));
  return 1 if (listsDiff($this->{_dns}, $that->{_dns}));
  return 1 if (listsDiff($this->{_wins}, $that->{_wins}));

  return 0;
}

sub needsRestart {
  my ($this, $that) = @_;

  return 1 if ($this->{_is_empty} ne $that->{_is_empty});
  return 1 if ($this->{_out_addr} ne $that->{_out_addr});
  return 1 if ($this->{_dhcp_iface} ne $that->{_dhcp_iface});
  return 1 if ($this->{_client_ip_start} ne $that->{_client_ip_start});
  return 1 if ($this->{_client_ip_stop} ne $that->{_client_ip_stop});
  return 1 if ($this->{_mtu} ne $that->{_mtu});
  
  return 0;
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

sub get_chap_secrets {
  my ($self) = @_;
  return (undef, "Authentication mode must be specified")
    if (!defined($self->{_auth_mode}));
  my @users = @{$self->{_auth_local}};
  return (undef, "Local user authentication not defined")
    if ($self->{_auth_mode} eq 'local' && scalar(@users) == 0);
  my $str = $cfg_delim_begin;
  if ($self->{_auth_mode} eq 'local') {
    while (scalar(@users) > 0) {
      my $user = shift @users;
      my $pass = shift @users;
      my $disable = shift @users;
      my $ip = shift @users;
      if ($disable eq 'disable') {
        my $cmd = "/opt/vyatta/bin/sudo-users/vyatta-kick-ravpn.pl" .
                  " \"$user\" 2> /dev/null";
        system ("$cmd");
      } else {
        if ($ip eq '') {
            $str .= ("\n$user\t" . 'pptpd' . "\t\"$pass\"\t" . '*');
        }
        else {
            $str .= ("\n$user\t" . 'pptpd' . "\t\"$pass\"\t" . "$ip");
        }
      }
    }
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
  my $rstr = '';
  if ($self->{_auth_mode} eq 'radius') {
    $rstr =<<EOS;
plugin radius.so
radius-config-file /etc/radiusclient-ng/radiusclient-pptp.conf
plugin radattr.so
EOS
  }
  my $str =<<EOS;
$cfg_delim_begin
name pptpd
ipparam pptp
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
EOS
  if (defined ($self->{_mtu})){
    $str .= "mtu $self->{_mtu}\n"
         .  "mru $self->{_mtu}\n";
  }
  $str .= "${rstr}$cfg_delim_end\n";
  return ($str, undef);
}

sub get_radius_conf {
  my ($self) = @_;
  my $mode = $self->{_auth_mode};
  return ("$cfg_delim_begin\n$cfg_delim_end\n", undef) if ($mode ne 'radius');

  my @auths = @{$self->{_auth_radius}};
  return (undef, "No Radius servers specified") if ((scalar @auths) <= 0);
  
  my $authstr = '';
  foreach my $auth (@auths) {
    $authstr .= "authserver      $auth\n";
  }
  my $acctstr = $authstr;
  $acctstr =~ s/auth/acct/g;

  my $str =<<EOS;
$cfg_delim_begin
auth_order      radius
login_tries     4
login_timeout   60
nologin /etc/nologin
issue   /etc/radiusclient-ng/issue
${authstr}${acctstr}servers         /etc/radiusclient-ng/servers-pptp
dictionary      /etc/radiusclient-ng/dictionary-ravpn
login_radius    /usr/sbin/login.radius
seqfile         /var/run/radius.seq
mapfile         /etc/radiusclient-ng/port-id-map-ravpn
default_realm
radius_timeout  10
radius_retries  3
login_local     /bin/login
$cfg_delim_end
EOS
  return ($str, undef);
}

sub get_radius_keys {
  my ($self) = @_;
  my $mode = $self->{_auth_mode};
  return ("$cfg_delim_begin\n$cfg_delim_end\n", undef) if ($mode ne 'radius');

  my @auths = @{$self->{_auth_radius}};
  return (undef, "No Radius servers specified") if ((scalar @auths) <= 0);
  my @skeys = @{$self->{_auth_radius_keys}};
  return (undef, "Key must be specified for Radius server")
    if ((scalar @auths) != (scalar @skeys));

  my $str = $cfg_delim_begin;
  while ((scalar @auths) > 0) {
    my $auth = shift @auths;
    my $skey = shift @skeys;
    $str .= "\n$auth                $skey";
  }
  $str .= "\n$cfg_delim_end\n";
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

  my $l2tp = new Vyatta::Config;
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
  my $listen = '';
  if (defined($self->{_out_addr})) {
    $listen = "listen $self->{_out_addr}\n";
  }
  if (defined($self->{_dhcp_iface})){
    return  (undef, "The specified interface is not configured for DHCP")
      if (!Vyatta::Misc::is_dhcp_enabled($self->{_dhcp_iface},0));
    my @dhcp_addr = Vyatta::Misc::getIP($self->{_dhcp_iface},4);
    my $ifaceip = pop(@dhcp_addr);
    @dhcp_addr = split(/\//, $ifaceip); 
    $ifaceip = $dhcp_addr[0];
    $listen = "listen $ifaceip\n" ;
  }
  
  my $str =<<EOS;
$cfg_delim_begin
option $ppp_opts
${listen}debug
noipparam
#logwtmp
localip 10.255.254.0
remoteip $ip_str
$cfg_delim_end
EOS
  return ($str, undef);
}

sub get_dhcp_conf {
  my ($self, $dhcp_conf) = @_;
  return ("", undef) if (!defined($self->{_dhcp_iface}));
  if (defined($self->{_dhcp_iface}) && defined($self->{_out_addr})){
   return (undef, "Only one of dhcp-interface and outside-address can be defined."); 
  }
  my $str =<<EOS;
#!/bin/sh
$cfg_delim_begin
CFGIFACE=$self->{_dhcp_iface}
/opt/vyatta/bin/sudo-users/vyatta-pptp-dhcp.pl --config_iface=\"\$CFGIFACE\" --interface=\"\$interface\" --new_ip=\"\$new_ip_address\" --reason=\"\$reason\" --old_ip=\"\$old_ip_address\"
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
  $str .= "\n  auth_mode " . $self->{_auth_mode};
  $str .= "\n  auth_local " . (join ",", @{$self->{_auth_local}});
  $str .= "\n  auth_radius " . (join ",", @{$self->{_auth_radius}});
  $str .= "\n  auth_radius_s " . (join ",", @{$self->{_auth_radius_keys}});
  $str .= "\n  dns " . (join ",", @{$self->{_dns}});
  $str .= "\n  wins " . (join ",", @{$self->{_wins}});
  $str .= "\n  empty " . $self->{_is_empty};
  $str .= "\n";

  return $str;
}

1;
