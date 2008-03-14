#!/usr/bin/perl

use strict;

my $username = shift;

my $SESSION_PATH = '/opt/vyatta/etc/ravpn/sessions';

if (!opendir(SDIR, "$SESSION_PATH")) {
  print STDERR "Cannot get session information\n";
  exit 1;
}
my @sessions = grep { /\@ppp/ } readdir(SDIR);
closedir(SDIR);
if ((scalar @sessions) <= 0) {
  # no sessions
  exit 1;
}

my @ips = ();
foreach my $ses (@sessions) {
  $ses =~ /^(.+)\@([^@]+)$/;
  my ($u, $intf) = ($1, $2);
  if ($u eq $username) {
    open(IP_ADDR, "ip addr show $intf |") or next;
    my $ip = undef;
    while (<IP_ADDR>) {
      next if (!/\s*inet/);
      /inet [\d.]+ peer ([\d.]+)\/32 /;
      $ip = $1;
    }
    close(IP_ADDR);
    if (defined($ip)) {
      push @ips, $ip;
    }
  }
}

foreach my $ip (@ips) {
  system("pkill -TERM -f 'pppd .*:$ip '");
}

exit 0;

