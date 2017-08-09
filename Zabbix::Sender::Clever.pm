package Zabbix::Sender::Clever;
use Data::Dumper;
use feature 'say';
use Moose;
extends 'Zabbix::Sender';

has 'debug' => (
    'is'    => 'rw',
    'isa'   => 'Bool',
    'default' => 0,
);

has 'dryrun' => (
    'is'    => 'rw',
    'isa'   => 'Bool',
    'default' => 0,
);
            
sub send {
  my $self=shift;
  my $item={'key'=>$_[0],'val'=>$_[1]};
  printf STDERR "Feeding item <<%s>> on host <<%s>> with value <<%s>>\n", 
                $item->{'key'}, $self->hostname, $item->{'val'} 
    if $self->debug;
  unless ($self->dryrun) {
    $self->SUPER::send(@_);
    say 'INFO: '.$self->_info if $self->debug;
  }  
}

1;
