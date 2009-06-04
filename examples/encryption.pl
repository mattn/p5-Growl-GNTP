use strict;
use warnings;
use lib qw/lib/;
use Net::Growl::GNTP;

binmode STDOUT, ':encoding(cp932)' if $^O eq 'MSWin32';

my $growl = Net::Growl::GNTP->new(
    AppName  => "my perl app",
    Password => $ENV{'GROWL_PASSWORD'} || '',
    EncryptAlgorithm => 'DES',
    #Debug => 1,
);

$growl->register([
    { Name => "foo", },
    { Name => "bar", },
]);

$growl->notify(
    Event => "foo",
    Title => "おうっふー おうっふー1",
    Message => "大事な事なので\n2回言いました",
    Icon => "http://mattn.kaoriya.net/images/logo.png",
);
