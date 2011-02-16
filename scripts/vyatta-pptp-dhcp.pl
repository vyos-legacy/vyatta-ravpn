#!/usr/bin/perl
use Getopt::Long;
use strict;

my $cfg_del_end = '### Vyatta PPTP VPN End ###';
my ($iface, $config_iface, $nip, $oip, $reason);
GetOptions("interface=s"    => \$iface,
           "config_iface=s"    => \$config_iface,
           "new_ip=s"       => \$nip,
           "old_ip=s"       => \$oip,
           "reason=s"       => \$reason);

# check if an update is needed
exit(0) if ($iface ne $config_iface);
exit(0) if (($oip eq $nip) && ($reason ne "BOUND"));
# open pptp config
open (my $FD, '<', "/etc/pptpd.conf");
my $str = '';
foreach my $line (<$FD>){
  $str .= $line;
}
# make substitution
if ($str =~ /listen/){
  $str =~ s/listen.*/listen $nip/g;
} else {
  $str =~ s/$cfg_del_end/listen $nip\n$cfg_del_end/g;
}
# write new pptp config
open (FD, '>', "/etc/pptpd.conf");
print FD $str;
close FD;
# restart the daemon
system("kill -TERM `pgrep -f 'pppd.* /etc/ppp/options\\.pptpd'` "
       . '>&/dev/null');
system("sudo /etc/init.d/pptpd stop");
system("sudo /etc/init.d/pptpd start");
