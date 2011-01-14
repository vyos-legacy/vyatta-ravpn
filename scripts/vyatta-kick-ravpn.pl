#!/usr/bin/perl

use strict;

my $username = shift;

my $SESSION_PATH = '/opt/vyatta/etc/ravpn/sessions';

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
  if ($u eq $username) {
    open(SFILE, "$SESSION_PATH/$ses") or next;
    my $pid = <SFILE>;
    close(SFILE);
    chomp($pid);
    next if (!($pid =~ /^\d+$/));
    push @pids, $pid;
  }
}

foreach my $pid (@pids) {
  kill('TERM', $pid);
}

exit 0;

