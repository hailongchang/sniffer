use v5.10;
use strict;
use warnings;
use autodie;
use Cwd;
use Getopt::Std;
use Data::Dumper;
use Carp;
use Time::Local;

my $pmap = {};
my $report = undef;
my $isinit = 1;


our $opt_p;
getopts("p:");

# 命令行选项，需要嗅探的本机IP，
my $SRVIP = $opt_p;

my %checkstate = (
    is_SYN          => sub{ $_[0] =~ m/SYN/i},
    is_FIN          => sub{ $_[0] =~ m/FIN/i},
    is_ACK          => sub{ $_[0] =~ m/ACK/i},
    is_PSH          => sub{ $_[0] =~ m/PSH/i},
    is_RST          => sub{ $_[0] =~ m/RST/i},
    now_established => sub{$pmap->{$_[1]}->{status} =~ /ESTABLISHED/i},
    now_synrcvd     => sub{$pmap->{$_[1]}->{status} =~ /SYN_RCVD/i},
    now_synsent     => sub{$pmap->{$_[1]}->{status} =~ /SYN_SENT/i},
    now_closewait   => sub{$pmap->{$_[1]}->{status} =~ /CLOSE_WAIT/i},
    now_closed      => sub{$pmap->{$_[1]}->{status} =~ /CLOSED/i},
    now_lastack     => sub{$pmap->{$_[1]}->{status} =~ /LAST_ACK/i},
    now_finwait1    => sub{$pmap->{$_[1]}->{status} =~ /Fin_WAIT1/i},
    now_timewait    => sub{$pmap->{$_[1]}->{status} =~ /TIME_WAIT/i},
    now_empty       => sub{$pmap->{$_[1]}->{status} eq ""},    
    );

while(1){
    while(<>){
	chomp();
	my($ts,$sr,$dt,$cn) = split/\t/;

	next unless defined $sr;
	next unless defined $dt;
	next unless defined $cn;
	next if($cn eq "");

	my($sip,$sport) = (split/:/,$sr)[0,1];
	my($dip,$dport) = (split/:/,$dt)[0,1];
	next unless defined $sport;
	next unless defined $dport;	    

	if($sip eq $SRVIP){
	    unless(exists $pmap->{$sport}){
		$pmap->{$sport} = {};
		$pmap->{$sport}->{status} = "";
		$pmap->{$sport}->{peerport} = "";
		$pmap->{$sport}->{peerip} = "";
		$pmap->{$sport}->{recvbytes} = 0;
		$pmap->{$sport}->{sendbytes} = 0;

	    }
	    $pmap->{$sport}->{peerport} = $dport;
	    $pmap->{$sport}->{peerip} = $dip;
	    &checkstatus($sport,$cn,0);
	    my($date,$time) = GetSpecTime($ts,'-');
	    $pmap->{$sport}->{last_time} = $date . " " . $time;
	    &OutputNetwork($sport,$sr,$dt,$cn);
	} 
	if($dip eq $SRVIP){
	    unless(exists $pmap->{$dport}){
		$pmap->{$dport} = {};
		$pmap->{$dport}->{status} = "";
		$pmap->{$dport}->{peerport} = "";
		$pmap->{$dport}->{peerip} = "";
		$pmap->{$dport}->{recvbytes} = 0;
		$pmap->{$dport}->{sendbytes} = 0;

	    }
	    $pmap->{$dport}->{peerport} = $sport;
	    $pmap->{$dport}->{peerip} = $sip;
	    &checkstatus($dport,$cn,1);
	    my($date,$time) = GetSpecTime($ts,'-');
	    $pmap->{$dport}->{last_time} = $date . " " . $time;
	    &OutputNetwork($dport,$sr,$dt,$cn);
	}    
    }
}


# 有限状态机
sub checkstatus{
    my($port,$desc,$isrecv) = @_;
    if($checkstate{is_PSH}->($desc,$port)){
	$pmap->{$port}->{status} = "ESTABLISHED";
	my $len = (split/=/,(split/\ /,$desc)[-1])[-1];
	if($isrecv == 1){
	    $pmap->{$port}->{recvbytes} += $len;
	}
	else{
	    $pmap->{$port}->{sendbytes} += $len;
	}
	return;
    }
    if($checkstate{is_RST}->($desc,$port)){
	$pmap->{$port}->{status} = "CLOSED" ;
	$pmap->{$port}->{peerip} = "";
	$pmap->{$port}->{peerport} = "";
	$pmap->{$port}->{recvbytes} = 0;
	$pmap->{$port}->{sendbytes} = 0;
	return;
    }
    if($isrecv == 1){
	if($checkstate{is_SYN}->($desc,$port)){
	    $pmap->{$port}->{status} = "SYN_RCVD" ;
	    return;
	}
	my $isfail = grep { $checkstate{$_}->($desc,$port) } qw/is_ACK now_synsent/;
	if($isfail == 2){
	    $pmap->{$port}->{status} = "ESTABLISHED";
	    return;
	}
	$isfail = grep { $checkstate{$_}->($desc,$port) } qw/is_FIN is_ACK/;
	if($isfail == 2){
	    if($pmap->{$port}->{status} eq "FIN_WAIT2"){
		$pmap->{$port}->{status} = "TIME_WAIT";
	    }
	    else{
		$pmap->{$port}->{status} = "CLOSE_WAIT";
	    }
	    return;
	}
	$isfail = grep { $checkstate{$_}->($desc,$port) } qw/is_ACK now_lastack/;
	if($isfail == 2){
	    $pmap->{$port}->{status} = "CLOSED";
	    $pmap->{$port}->{peerip} = "";
	    $pmap->{$port}->{peerport} = "";
	    $pmap->{$port}->{recvbytes} = 0;
	    $pmap->{$port}->{sendbytes} = 0;
	    return;
	}
	$isfail = grep { $checkstate{$_}->($desc,$port) } qw/is_ACK now_finwait1/;
	if($isfail == 2){
	    $pmap->{$port}->{status} = "FIN_WAIT2";
	    return;
	}
    }
    else{
	my $isfail = grep { $checkstate{$_}->($desc,$port) } qw/is_SYN is_ACK now_synrcvd/;
	if($isfail == 3){
	    $pmap->{$port}->{status} = "SYN_SENT";
	    return;
	}
	$isfail = grep { $checkstate{$_}->($desc,$port) } qw/is_FIN is_ACK now_closewait/;
	if($isfail == 3){
	    $pmap->{$port}->{status} = "LAST_ACK";
	    return;
	}
	$isfail = grep { $checkstate{$_}->($desc,$port) } qw/is_FIN is_ACK now_established/;
	if($isfail == 3){
	    $pmap->{$port}->{status} = "FIN_WAIT1";
	    return;
	}
	$isfail = grep { $checkstate{$_}->($desc,$port) } qw/is_ACK now_timewait/;
	if($isfail == 2){
	    $pmap->{$port}->{status} = "CLOSED";
	    $pmap->{$port}->{peerip} = "";
	    $pmap->{$port}->{peerport} = "";
	    $pmap->{$port}->{recvbytes} = 0;
	    $pmap->{$port}->{sendbytes} = 0;
	    return;
	}
    }
}

sub OutputNetwork{
    my($port,$sr,$dt,$cn) = @_;
    if(exists $pmap->{$port}){
	say $pmap->{$port}->{last_time},
        "\t",$sr,
        "\t",$dt,
        "\t",$pmap->{$port}->{status},
        "\t",$cn,
        "\t",$pmap->{$port}->{sendbytes}," ",$pmap->{$port}->{recvbytes};
    }
}


sub GetSpecTime{
    my($ts,$delimiter) = @_;

    $delimiter = '' unless defined $delimiter;
    my($sec,$min,$hour,$mday,$mon,$year,undef,undef,undef) = localtime($ts);

    return(
	($year + 1900) . $delimiter . 
	(((++$mon) < 10) ? ("0" . $mon) : ($mon)) . $delimiter . 
	((($mday) < 10 ) ? ("0" . $mday) : ($mday)),

	((($hour) < 10 ) ? ("0" . $hour) : ($hour)) . ":" . 
	((($min) < 10 ) ? ("0" . $min) : ($min)) . ":" .
	((($sec) < 10 ) ? ("0" . $sec) : ($sec))
	);
    
}

