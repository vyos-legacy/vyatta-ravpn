#!/usr/bin/perl
use Getopt::Long;
use strict;

my $config_file = "/etc/ipsec.d/tunnels/remote-access";
my $secrets_file = "/etc/ipsec.secrets";
my $l2tp_file = "/etc/xl2tpd/xl2tpd.conf";
my $cfg_del_end = '### Vyatta L2TP VPN End ###';
my ($iface, $config_iface, $nip, $oip, $reason);
GetOptions("interface=s"    => \$iface,
           "config_iface=s"    => \$config_iface,
           "new_ip=s"       => \$nip,
           "old_ip=s"       => \$oip,
           "reason=s"       => \$reason);

# check if an update is needed
exit(0) if ($iface ne $config_iface);
exit(0) if (($oip eq $nip) && ($reason ne "BOUND"));
logger("DHCP address updated to $nip from $oip: Updating ipsec configuration.");

# open l2tp config
open (my $FD, '<', $l2tp_file);
my $str = '';
foreach my $line (<$FD>){
  $str .= $line;
}
close $FD;
# make substitution
if ($str =~ /listen-addr/){
  $str =~ s/listen-addr = .*/listen-addr = $nip/g;
} else {
  $str =~ s/\[global\]/\[global\]\nlisten-addr $nip/g;
}
# write new l2tp config
open (my $FD, '>', $l2tp_file);
print ${FD} $str;
close $FD;

# open ipsec config
open (my $FD, '<', $config_file);
my $str = '';
foreach my $line (<$FD>){
  $str .= $line;
}
close($FD);
# make substitution
if ($str =~ /left=/){
  $str =~ s/left=.*/left=$nip/g;
} else {
  $str =~ s/$cfg_del_end/left=$nip\n$cfg_del_end/g;
}
# output new ipsec.conf
open my $output_config, '>', $config_file
    or die "Can't open $config_file: $!";
print ${output_config} $str;
close $output_config;

# change ipsec.secrets
open (my $FD, '<', $secrets_file);
my @lines = <$FD>;
close $FD;
open my $output_secrets, '>', $secrets_file
  or die "Can't open $secrets_file";
foreach my $line (@lines){
  if (($line =~ /(.*)\#dhcp-ra-interface=(.*)\#/) && ($2 eq $iface)){
    my $secretline = $1;
    $secretline =~ /(.*?) (.*?) : PSK (.*)/;
    $line = "$nip $2 : PSK $3\#dhcp-ra-interface=$iface\#\n";
  }
  print ${output_secrets} $line;
}
close $output_secrets;
system("kill -TERM `pgrep -f 'name VyattaL2TPServer'` >&/dev/null");
system ("/usr/sbin/ipsec rereadall");
system ("/usr/sbin/ipsec update");
system("sudo /etc/init.d/xl2tpd stop");
system("sudo /etc/init.d/xl2tpd start");

sub logger {
  my $msg = pop(@_);
  my $FACILITY = "daemon";
  my $LEVEL = "notice";
  my $TAG = "ipsec-dhclient-hook";
  my $LOGCMD = "logger -t $TAG -p $FACILITY.$LEVEL";
  system("$LOGCMD $msg");
}
