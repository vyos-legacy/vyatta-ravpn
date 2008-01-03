#!/usr/bin/perl

use strict;

my $SESSION_PATH = '/opt/vyatta/etc/ravpn/sessions';
my $L2TP_LOCAL = '10.255.255.0';
my $PPTP_LOCAL = '10.255.254.0';

if (!opendir(SDIR, "$SESSION_PATH")) {
  print STDERR "Cannot get session information\n";
  exit 1;
}
my @sessions = grep { /\@ppp/ } readdir(SDIR);
closedir(SDIR);
if ((scalar @sessions) <= 0) {
  print "No active remote access VPN sessions\n";
  exit 0;
}

my %if_hash = ();
my %if_time_hash = ();
foreach my $ses (@sessions) {
  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
      $atime,$mtime,$ctime,$blksize,$blocks) = stat("$SESSION_PATH/$ses");
  $ses =~ /^([^@]+)\@(.+)$/;
  $if_hash{$2} = $1;
  $if_time_hash{$2} = $mtime;
}

sub read_stat {
  my $file = shift;
  open(IF, "<$file") or return 'N/A';
  my $stat = <IF>;
  close(IF);
  return 'N/A' if (!defined($stat));
  chomp($stat);
  if ($stat > 1000000000) {
    $stat = sprintf('%.1fG', ($stat / 1000000000));
  } elsif ($stat > 1000000) {
    $stat = sprintf('%.1fM', ($stat / 1000000));
  } elsif ($stat > 1000) {
    $stat = sprintf('%.1fK', ($stat / 1000));
  }
  return $stat;
}

print <<EOH;
Active remote access VPN sessions:

User       Time      Proto Iface Remote IP       TX pkt/byte   RX pkt/byte
---------- --------- ----- ----- --------------- ------ ------ ------ ------
EOH
foreach my $intf (keys %if_hash) {
  my $user = $if_hash{$intf};
  my $proto = 'N/A';
  my ($local, $remote) = ('N/A', 'N/A');

  open(IP_ADDR, "ip addr show $intf |") or next;
  while (<IP_ADDR>) {
    next if (!/\s*inet/);
    /inet ([\d.]+) peer ([\d.]+)\/32 /;
    ($local, $remote) = ($1, $2);
  }
  close(IP_ADDR);

  if ($local eq $L2TP_LOCAL) {
    $proto = 'L2TP';
  } elsif ($local eq $PPTP_LOCAL) {
    $proto = 'PPTP';
  }
  
  my $dur = time() - $if_time_hash{$intf};
  my $day = ($dur < (3600 * 24)) ? 0 : int($dur / (3600 * 24));
  $dur %= (3600 * 24);
  my $hour = ($dur < 3600) ? 0 : int($dur / 3600);
  $dur %= 3600;
  my $min = ($dur < 60) ? 0 : int($dur / 60);
  my $tstr = sprintf '%02ud%02uh%02um', $day, $hour, $min;
  if ($day == 0) {
    $dur %= 60;
    $tstr = sprintf '%02uh%02um%02us', $hour, $min, $dur;
  }

  my $sdir = "/sys/class/net/$intf/statistics";
  my $tx_p = read_stat("$sdir/tx_packets");
  my $tx_b = read_stat("$sdir/tx_bytes");
  my $rx_p = read_stat("$sdir/rx_packets");
  my $rx_b = read_stat("$sdir/rx_bytes");

  printf "%-10s %-9s %-5s %-5s %-15s %6s %6s %6s %6s\n",
         $user, $tstr, $proto, $intf, $remote, $tx_p, $tx_b, $rx_p, $rx_b;
}

exit 0;

