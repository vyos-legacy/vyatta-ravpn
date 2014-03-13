#!/usr/bin/perl

use strict;
use Getopt::Long;

my $username = undef;
my $interface  = undef;
my $protocol = undef;

my $SESSION_PATH = '/opt/vyatta/etc/ravpn/sessions';

GetOptions(
  "username=s" => \$username,
  "interface=s" => \$interface,
  "protocol=s" => \$protocol
);

if ( (defined $username) && (defined $interface) ) {
  print STDERR "Please specify either interface or user name\n";
  exit 1;
}

if (!opendir(SDIR, "$SESSION_PATH")) {
  print STDERR "Cannot get session information\n";
  exit 1;
}
my @l2tpsessions = grep { /\@l2tp/ } readdir(SDIR);
if (!opendir(SDIR, "$SESSION_PATH")) {
  print STDERR "Cannot get session information\n";
  exit 1;
}
my @pptpsessions = grep { /\@pptp/ } readdir(SDIR);
my @sessions = (@l2tpsessions, @pptpsessions);
closedir(SDIR);
if ((scalar @sessions) <= 0) {
  # no sessions
  exit 1;
}

my @pids = ();
foreach my $ses (@sessions) {
  $ses =~ /^(.+)\@([^@]+)$/;
  my ($u, $intf) = ($1, $2);
  if (defined $interface){
    if ($intf eq $interface) {
      open(my $SFILE, '<', "$SESSION_PATH/$ses") or next;
      my $pid = <$SFILE>;
      close($SFILE);
      chomp($pid);
      next if (!($pid =~ /^\d+$/));
      push @pids, $pid;
    }
  }
  else {
    if ($u eq $username or $username eq "all_users") {
      if (defined $protocol) {
        if ( $intf !~ /^$protocol\d+/ ) {
          next;
        }
      }
      open(my $SFILE, '<', "$SESSION_PATH/$ses") or next;
      my $pid = <$SFILE>;
      close($SFILE);
      chomp($pid);
      next if (!($pid =~ /^\d+$/));
      push @pids, $pid;
    }
  }
}

foreach my $pid (@pids) {
  kill('TERM', $pid);
}

exit 0;

