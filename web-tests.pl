#!/usr/bin/perl
package WT;
use 5.16.1;
use strict;
use utf8;
use Data::Dumper;
use Mojo::UserAgent;
use CBOR::XS qw(encode_cbor decode_cbor);
use Zabbix::Sender::Clever;
use JSON::XS;
use Try::Tiny;
use Net::Ping;
use Math::Round qw(nearest);
use Time::HiRes qw(time);
use Carp qw(croak carp);

use constant {
  WT_SUCCESS=>0,
  WT_FAILED=>1,
  WT_UNKNOWN=>2,
  WT_STEP_KEY_FMT=>q(wt_step_%s["%s","%s"]),
  WT_STEPS_DISCOVERY_FMT=>q(wt["%s"].steps),
  USER_AGENT_CONN_TIMEOUT=>30,
  USER_AGENT_INACT_TIMEOUT=>40,
  FL_WIDE_UTF8_TO_BYTES=>0,
};

my %webChecks;

sub jsdump {
  say STDERR JSON::XS->new->pretty->encode(ref($_[0])?$_[0]:[$_[0]]);
}

sub doPrepareSSLConnection {
  my ($ua,$sslConf)=@_;
  $ua->ca($sslConf->{'ca_cert'}) if $sslConf->{'ca_cert'};
  $ua->cert($sslConf->{'client_cert'}) if $sslConf->{'client_cert'};
  $ua->key($sslConf->{'client_key'}) if $sslConf->{'client_key'};
}

sub run_content_checks {
  my ($chkList, $rqRes)=@_;
  %webChecks=(
    'fixed_string'=>{
      'descr'=>'Fixed string match',
      'worker'=>sub {
        my ($rqRes,$args)=@_;
        my $strNotFound;
        my $text=$rqRes->body;
        for (ref($args) eq 'ARRAY'?@{$args}:($args)) {
          if (index($text, $_)<0) {
            $strNotFound=$_;
            last
          }
        }
        return defined($strNotFound)
          ? {'error'=>qq(char string "$strNotFound" not found)}
          : undef
      },
    },
    'code'=>{
      'descr'=>'HTTP retcode',
      'worker'=>sub {
        my ($rqRes,$args)=@_;
        my $rxCheckCode=ref($args) eq 'ARRAY'?'(?:'.join('|'=>@{$args}).')':$args;
        $rxCheckCode=qr/^${rxCheckCode}$/;
        return $rqRes->code!~$rxCheckCode
          ? {'error'=>sprintf('code %s not appropriate', $rqRes->code)}
          : undef;
      },
    },
  ) unless %webChecks;
  
  for my $resChk (@{$chkList}) {
    for my $chkType (grep exists($webChecks{lc($_)}), keys %{$resChk}) {
      my $chkRes=$webChecks{lc($chkType)}{'worker'}->($rqRes, $resChk->{$chkType});
      return sprintf('ERROR: check "%s" not passed: %s', $webChecks{lc($chkType)}{'descr'}, $chkRes->{'error'})
          if $chkRes and $chkRes->{'error'};
    }
  }
  return 'OK'
}

my %rightParen;
sub macro_subst {
  %rightParen=(
    '<<' => '>>',
    '{{'  => '}}',
    '(' => ')',
    '<' => '>',
  ) unless %rightParen;
  my ($macroses,$leftParen)=@_[1..$#_];
  my ($lp,$rp)=$leftParen
    ? ($leftParen, ( $rightParen{$leftParen} || $leftParen ))
    : ('{','}');
    
#  say "L=$lp, R=$rp, macroses=".Dumper($macroses);
  for my $macro (keys %{$macroses}) {
    my $subst=ref($macroses->{$macro})?$macroses->{$macro}[0]:$macroses->{$macro};
    $_[0]=~s/\Q${lp}\E${macro}\Q${rp}\E/$subst/g;
  }
}

my $DEBUG;
sub dbg_ {
  my $when=shift;
  say '[',scalar(localtime),'] ', join('//'=>map uc(substr($_,0,1)).':'.$when->{$_}, grep { exists($when->{$_}) and defined($when->{$_}) } qw(host test step)), "\n\t>>> ", sprintf($_[0], @_[1..$#_])
    if $DEBUG;
}

sub extract_vars {
  my ($body, $rules)=@_;
  return map {
    my $rx=qr/$rules->{$_}/;
    $_=>[$body=~m/${rx}/]
  } keys %{$rules}
}

sub run_tests {
  my $fh=shift;
  close $fh;
  
  my ($siteConf,$pars)=((map decode_cbor($_), @_),{},{});
  my $where={'host'=>$siteConf->{'host'}};
  $DEBUG=$pars->{'debug'};
  try {
    my $ua=Mojo::UserAgent->new;
    $ua->connect_timeout(USER_AGENT_CONN_TIMEOUT);
    $ua->inactivity_timeout(USER_AGENT_INACT_TIMEOUT);
    my $Z=Zabbix::Sender::Clever->new(
      'server'=>$pars->{'server'},
      'debug'=>$pars->{'debug'},
      'dryrun'=>$pars->{'dryrun'},
      'hostname'=>$siteConf->{'host'}
    );
    my %macro;
    if ($siteConf->{'url'}) {
      my $url=$macro{'BASE_URL'}=$siteConf->{'url'};
      if (my ($flUseSSL,$urlHost,$urlPortExpl)=$url=~m%^\s*http(s?)://(?:[^/@]+@)?([^/:]+)(?::(\d+))?$%i) {
        my $portNumber=$urlPortExpl || ($flUseSSL?443:80);
        my $pinger=Net::Ping->new();
        $pinger->port_number($portNumber);
        my $flHostAccessible=$pinger->ping($urlHost);
        $Z->send('web.tcp.reachable', $flHostAccessible?1:0);
        return unless $flHostAccessible;
      }
    }
    doPrepareSSLConnection($ua, $siteConf->{'ssl'}) if $siteConf->{'ssl'};
    my %wtAllRes;
    for my $wt (grep { !exists($_->{'enable'}) or $_->{'enable'} } @{$siteConf->{'tests'}}) {
      @{$where}{qw(test step)}=($wt->{'name'},undef);
      my @wtSteps=@{$wt->{'steps'}};
      my $step_n=0;
      my $wtResult={};
      my %extracts;
      WT_STEPS:
      for (;$step_n<=$#wtSteps;$step_n++) {
        my $wtStep=$wtSteps[$step_n];
        my $stepName=$where->{'step'}=$wtStep->{'name'};
        
        my $oldUARedirects=( defined $wtStep->{'redirects'} and eval { $wtStep->{'redirects'} =~ /^\d+$/ } )
          ? do { $_=$ua->max_redirects;
                 dbg_ $where, 'Setting number of redirects to %d', my $n=$wtStep->{'redirects'};
                 $ua->max_redirects($n);
                 $_
              }
          : undef;        

        my $url=$wtStep->{'url'};
        macro_subst($url,\%macro);
        do {
          for (qw(get post put head delete patch)) {
            do { 
              $wtStep->{'method'}=uc $_;
              last
            } if exists $wtStep->{$_} and defined $wtStep->{$_}
          }
        } unless $wtStep->{'method'} and ! ref($wtStep->{'method'}) and $wtStep->{'method'}=~m/(?:P(?:OST|UT|ATCH)|GET|HEAD|DELETE)/i;
        my $rqMethod=$wtStep->{'method'} || 'GET';
        dbg_ $where, "Used request method: $rqMethod";
        my $stepStart=time;
        my $tx=$ua->start($ua->build_tx(
            $rqMethod => $url,
            $wtStep->{'headers'}?($wtStep->{'headers'}):(),
            (exists $wtStep->{lc $rqMethod} and ref($wtStep->{lc $rqMethod}) eq 'HASH')
              ? do {
                  if (my $frm=$wtStep->{lc $rqMethod}{'form'}) {
                    for ( grep /\<\</, values %{$frm} ) {
#                      say 'Before macro '.$_;
                      macro_subst($_, \%extracts, '<<');
#                      say 'After macro '.$_;
                    }
                    dbg_ $where, 'Sending form: %s', Dumper($frm);
                  }
                  %{$wtStep->{lc $rqMethod}}
                }
              : (),
        ));
        my $err=$tx->error;
        if ($err and !(($err->{'code'} and $wtStep->{'code'}==$err->{'code'}) or $wtStep->{'error_expected'})) {
          $wtResult->{$stepName}{'val'}='ERROR '.join(': '=>grep defined, @{$err}{qw/code message/});
          last WT_STEPS
        }
        my $res=eval { $tx->result };
        my $stepFin=time;
        $wtResult->{$stepName}={
          'time'=>$stepFin>$stepStart?nearest(1,($stepFin-$stepStart)*1000):-1
        };
        $ua->max_redirects($oldUARedirects) if $oldUARedirects;
        if ( $res and (my $resBody=eval { $res->body }) and $wtStep->{'extract'} ) {
          %extracts=(%extracts, extract_vars($resBody, $wtStep->{'extract'}));
#          dbg_ $where, 'Extracts: '.Dumper(\%extracts);
        }
        last unless ( $wtResult->{$stepName}{'val'}=
          $wtStep->{'checks'}
            ? run_content_checks($wtStep->{'checks'},$res)
            : (($wtStep->{'code'} and $res->code and $res->code eq $wtStep->{'code'}) or (!$wtStep->{'code'} and $res->is_success))
              ? 'OK'
              : 'ERROR '.$res->code.($res->message?': '.$res->message:'') ) eq 'OK';
        utf8::encode($wtResult->{$stepName}{'val'}) if FL_WIDE_UTF8_TO_BYTES;
      }
      $wtResult->{$_->{'name'}}{'val'}='UNKNOWN' for @wtSteps[($step_n+1)..$#wtSteps];
      $wtAllRes{$wt->{'name'}}=$wtResult;
    }
    delete @{$where}{'test','step'};
    
    while (my ($wtName, $wtRes)=each %wtAllRes) {
      while (my ($wtStepName, $wtStepRes)=each %{$wtRes}) {
        $Z->send(sprintf(WT_STEP_KEY_FMT, $_, $wtName, $wtStepName), $wtStepRes->{$_})
          for grep defined $wtStepRes->{$_}, qw(time val);
      }
    }
  } catch {
    croak 'Catched error when run_tests(): '.$_;
  };
}

sub get_discovery {
  my $fh=shift;
  close $fh;
  my ($siteConf,$pars)=map decode_cbor($_), @_[0,1];
  my $Z=Zabbix::Sender::Clever->new(
    'server'=>$pars->{'server'},
    'debug'=>$pars->{'debug'},
    'dryrun'=>$pars->{'dryrun'},
    'hostname'=>$siteConf->{'host'}
  );  

  $Z->send('wt.discovery',JSON::XS->new->encode(
    {'data'=>[
      map {
        my $wtName=$_->{'name'};
        map {
          '{#WT_NAME}'=>$wtName,
          '{#WT_STEP}'=>$_->{'name'},
        }, @{$_->{'steps'}}    
      } @{$siteConf->{'tests'}}
    ]}
  ));
}

package main;
use utf8;
use strict;
use warnings;
use 5.16.1;

use POSIX ":sys_wait_h";
use Mojo::UserAgent;
use CBOR::XS qw(encode_cbor decode_cbor);
use AnyEvent::Fork::Template;
use Getopt::Long::Descriptive;
use Data::Dumper;

use constant {
  ZA_CONF=>'/etc/zabbix/zabbix_agentd.conf',
  DFLT_SCENARIO_FILE=>'/etc/zabbix/wt/checks.pl',
  DFLT_WEB_TESTS_DIR=>'/etc/zabbix/wt',
};

open my $fhZAConf, '<', ZA_CONF or die 'Cant open '.ZA_CONF.': '.$!;
my $zbxServer;
for (<$fhZAConf>) {
  next unless /^\s*Server/ and ($zbxServer)=m%^\s*Server\s*=\s*([^,\s#]+(?:,[^,\s#]+)*)%
}
$zbxServer||='localhost';

my %method2sub=(
  'discovery'=>'get_discovery',
  'test'=>'run_tests'
);
 
my ($opts, $usage) = describe_options(
  $0.' %o [-m (discovery|test)]
          [-x|--debug]
          [-t|--dryrun|--test]
          [--help]' =>
  [ 'debug|x'		=>   	q(turn on debugging) ],
  [ 'dryrun|t'		=>  	q(dont do anything, just test) ],
  [ 'method|m=s'     	=> 	'what to do. supported values: '.join(','=>map qq("$_"), keys %method2sub), { 'default'=>'discovery' } ],
  [ 'checksfile|f=s'	=>	q{file describing webtests definitions. mutually exclusive with the --checksdir (-d) option} ],
  [ 'checksdir|d=s'	=>	q{path to the directory containing files describing webtests definitions. mutually exclusive with the --checksfile (-f) option}, { 'default'=>DFLT_WEB_TESTS_DIR } ],
  [],
  [ 'verbose|v'		=>	q(print extra stuff) ],
  [ 'help'		=>      q(print usage message and exit), { 'shortcircuit' => 1 } ],
);
 
print($usage->text), exit if $opts->help;
my ($flDebug,$flTest,$flVerbose)=($opts->debug,$opts->dryrun,$opts->verbose);

$ENV{'MOJO_USERAGENT_DEBUG'}=($flDebug || $flVerbose)?1:0;

die 'You couldnot specify both --checksfile and --checksdir' if $opts->checksfile && $opts->checksdir;
my %checks=$opts->checksfile
  ? (do($opts->checksfile) or die 'Cant proceed with checks scenario: '.$! )
  : do {
      my $t;
      map { substr($_,$t=rindex($_,'/')+1,length($_)-($t+3))=>do($_) } glob($opts->checksdir.'/*.wt');
    };
die sprintf("Unknown method <<%s>>,\nSupported methods: %s\nUsage: %s", $opts->method, join(', '=>keys %method2sub), $usage->text)
  unless my $what2do=$method2sub{lc $opts->method};

unless ( grep {! exists($_->{'enable'}) or $_->{'enable'} } values %checks ) {
  say STDERR 'There are no checks enabled, exiting';
  exit 0
}

my $cv=AE::cv;
while (my ($siteName, $siteCheck)=each %checks) {
  next if exists($siteCheck->{'enable'}) and !$siteCheck->{'enable'};
  $cv->begin;
  $AnyEvent::Fork::Template
    ->fork
    ->send_arg(encode_cbor $siteCheck)
    ->send_arg(encode_cbor {
      'server'=>$zbxServer,
      'debug'=>$flDebug?1:0,
      'dryrun'=>$opts->dryrun?1:0,
    })
    ->run('WT::'.$what2do,
          sub { $cv->end }
    );
}

my $fh=$cv->recv;
1 while waitpid(-1, WNOHANG) > 0;
 