# Copyright (C) 2006, 2007; David Muir Sharnoff

package SyslogScan::Daemon::SpamDetector::Postfix;

use strict;
use warnings;
use SyslogScan::Daemon::SpamDetector::Plugin;
use Plugins::SimpleConfig;
use Tie::Cache::LRU;
our $msgcachesize = 3_000;
our(@ISA) = qw(SyslogScan::Daemon::SpamDetector::Plugin);

my %defaults = (
	rx_extra	=> '.',
	rx_month	=> '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)',
	rx_date		=> '',
	logfile		=> '/var/log/mail.log',
	debug		=> 0,
	msgcachesize	=> sub {
		my ($pkgself, $key, $value) = @_;
		if (ref($pkgself)) {
			$pkgself->{msgcachesize} = $value;
			if ($pkgself->{msgcache}) {
				my $t = tied(%{$pkgself->{msgcache}});
				$t->max_size($value);
			}
		} else {
			$msgcachesize = $value;
		}
	},
);

sub config_prefix { 'sdpostfix_' }

sub parse_config_line { simple_config_line(\%defaults, @_); }

sub new 
{
	my $self = simple_new(\%defaults, @_); 
	$self->{msgcache} = {};
	die if ref($self->{msgcachesize});
	tie %{$self->{msgcache}}, 'Tie::Cache::LRU', $self->{msgcachesize} || $msgcachesize;
	return $self;
}

our $Mon;
our $Date;
our $iprx;

sub preconfig
{
	my $self = shift;
	$self->{Mon} = qr/$self->{rx_month}/;
	$self->{Date} = $self->{rx_date} ? qr/$self->{rx_date}/ : qr/$self->{Mon} [ 1-3][0-9] \d\d:\d\d:\d\d/;
	$self->{Extra} = qr/$self->{rx_extra}/;
}

sub get_logs
{
	my $self = shift;
	my $Date = $self->{Date};
	return (
		# Oct 24 14:19:27 ravel postfix/smtpd[968]: D4E5E1DC379: client=outbound1.internet-mail-service.net[216.240.47.192]
		# Oct 24 14:19:27 ravel postfix/cleanup[94003]: D4E5E1DC379: message-id=<200610242119.k9OLJR7l031900@idiom.com>
		$self->{logfile}	=> [
			qr{^$Date (\S+) postfix\S*/smtpd\[\d+\]: ([A-Z0-9]{9,11}): (client)=(\S*)\[([\d\.]{8,20})\]},
			qr{^$Date (\S+) postfix\S*/cleanup\[\d+\]: ([A-Z0-9]{9,11}): (message-id)=<(.*?)>},
		],
	);
}

sub parse_logs
{
	my ($self, $logfile, $rx) = @_;
	my $debug = $self->{debug};
	my $logline = $_;
	my ($host, $msg, $what) = ($1, $2, $3);
	
	my $queueid = "$host/$msg";

	if ($self->{Extra} && ! /$self->{Extra}/) {
		print "Ignoring match of $logline\n" if $debug;
	} elsif ($what eq 'client') {
		my ($hostname, $ip) = ($4, $5);
		$self->{msgcache}{$queueid}{ip} = $ip;
		if ($self->{msgcache}{$queueid}{msgid}) {
			for my $msgid (@{$self->{msgcache}{$queueid}{msgid}}) {
				$self->process_spam_match(
					id		=> $msgid,
					ip		=> $ip,
					status		=> 'idmap',
					match		=> 'Postfix',
					host		=> $host,
					relayname	=> $hostname,
				);
			}
		}
	} else {
		my ($id) = ($4);
		if ($self->{msgcache}{$queueid}{ip}) {
			$self->process_spam_match(
				id	=> $id,
				ip	=> $self->{msgcache}{$queueid}{ip},
				status	=> 'idmap',
				match	=> 'Postfix',
				host	=> $host,
			);
		} else {
			push(@{$self->{msgcache}{$queueid}{msgid}}, $id);
		}
	}
	return;
}

1;

=head1 NAME

 SyslogScan::Daemon::SpamDetector::Postfix - record incomming messages

=head1 SYNOPSIS

 plugin SyslogScan::Daemon::SpamDetector as sd_

 sd_plugin SyslogScan::Daemon::SpamDetector::Postfix
	debug 		0
	logfile		/var/log/mail.info
	msgcachesize	3000
	rx_extra	'ingore_lines_without_this_string'

=head1 DESCRIPTION

SyslogScan::Daemon::SpamDetector::Postfix watches the mail log file and
notices which Message-IDs came from which IP address.

=head1 CONFIGURATION PARAMETERS

The following configuration parameters are supported:

=over 4

=item debug

Debugging on (1) or off (0).

=item logfile

Which logfile to watch (default: C</var/log/mail.log>).

=item msgcachesize

To do this mapping, multiple log lines must be matched.  Partial
matches will be stored in a cache.  This parameter sets the
size of the cache (default: 3000).

=item rx_extra

Ignore log lines that don't match a regular expression.  Note: this module
looks for two different kinds of Postfix log lines the regular expression
needs to work for both sets.  One kind of log line always includes 
C<: client=> and the other always includes C<: message-id=>.

=back

=head1 SEE ALSO

L<SyslogScan::Daemon::SpamDetector>
L<SyslogScan::Daemon::SpamDetector::Sendmail>

=head1 THANK THE AUTHOR

If you need high-speed internet services (T1, T3, OC3 etc), please 
send me your request-for-quote.  I have access to very good pricing:
you'll save money and get a great service.

=head1 LICENSE

Copyright(C) 2006 David Muir Sharnoff <muir@idiom.com>. 
This module may be used and distributed on the same terms
as Perl itself.

