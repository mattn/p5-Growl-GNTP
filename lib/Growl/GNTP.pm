package Growl::GNTP;

use strict;
use warnings;
use IO::Socket::INET;
use Data::UUID;
use Crypt::CBC;
use Digest::MD5 qw/md5_hex/;
use Digest::SHA qw/sha1_hex sha256_hex/;
our $VERSION = '0.06';

sub new {
    my $class = shift;
    my %args  = @_;
    $args{Proto}    ||= 'tcp';
    $args{PeerHost} ||= 'localhost';
    $args{PeerPort} ||= 23053;
    $args{AppName}  ||= 'Growl::GNTP';
    $args{AppIcon}  ||= '';
    $args{Password} ||= '';
    $args{PasswordHashAlgorithm} ||= 'MD5';
    $args{EncryptAlgorithm}      ||= 'NONE';
    $args{Debug}                 ||= 0;
    $args{Callbacks} = [];
    srand();
    bless {%args}, $class;
}

sub register {
    my $self = shift;
    my $notifications = shift || [];

    my $AppName = $self->{AppName};
    $AppName =~ s!\r\n!\n!;
    my $AppIcon = $self->{AppIcon};
    $AppIcon =~ s!\r\n!\n!;
    my $count = scalar @$notifications;

    my $sock  = IO::Socket::INET->new(
        PeerAddr => $self->{PeerHost},
        PeerPort => $self->{PeerPort},
        Proto    => $self->{Proto},
    );
    die $@ unless $sock;

    my $form = <<EOF;
Application-Name: $AppName
Application-Icon: $AppIcon
Notifications-Count: $count

EOF
    $form =~ s!\n!\r\n!g;

    $count = 0;
    for my $notification ( @{$notifications} ) {
        $count++;
        my %data = (
            Name => $notification->{Name} || "Growl::GNTP Notify$count",
            DisplayName => $notification->{DisplayName}
              || $notification->{Name} || "Growl::GNTP Notify$count",
            Enabled => _translate_bool($notification->{Enabled} || 'True'),
            Sticky => _translate_bool($notification->{Sticky} || 'True'),
            Priority => _translate_int($notification->{Priority} || 0),
        );
        $data{$_} =~ s!\r\n!\n! for ( keys %data );

        my $subform .= <<EOF;
Notification-Name: \$(Name)
Notification-Display-Name: \$(DisplayName)
Notification-Enabled: \$(Enabled)
Notification-Sticky: \$(Sticky)
Notification-Priority: \$(Priority)

EOF
        $subform =~ s!\n!\r\n!g;
        $subform =~ s/\$\((\w+)\)/$data{$1}/ge;
        $form .= $subform;
    }
    $form = _gen_header($self, 'REGISTER', $form);
    $sock->send($form);

    my $ret = '';
    while (<$sock>) {
        $_ =~ s!\r\n!!g;
        print "$_\n" if $self->{Debug};
        $ret  = $1 if $_ =~ /^GNTP\/1.0 -(\w+).*$/;
        last if length($_) == 0;
    }
    close $sock;
    return $ret eq 'OK';
}

sub notify {
    my ( $self, %args ) = @_;
    my %data = (
        AppName             => $self->{AppName},
        Event               => $args{Event} || '',
        Title               => $args{Title} || '',
        Message             => $args{Message} || '',
        Icon                => $args{Icon} || '',
        CallbackContextType => $args{CallbackContextType} || '',
        CallbackContext     => $args{CallbackContext} || '',
        CallbackFunction    => $args{CallbackFunction} || {},
    );
    $data{$_} =~ s!\r\n!\n! for ( keys %data );

    my $sock = IO::Socket::INET->new(
        PeerAddr => $self->{PeerHost},
        PeerPort => $self->{PeerPort},
        Proto    => $self->{Proto},
    );
    die $@ unless $sock;

    my $form = <<EOF;
Application-Name: \$(AppName)
Notification-Name: \$(Event)
Notification-Title: \$(Title)
Notification-Text: \$(Message)
Notification-Icon: \$(Icon)
Notification-Callback-Context: \$(CallbackContext)
Notification-Callback-Context-Type: \$(CallbackContextType)
EOF
    $form =~ s!\n!\r\n!g;
    $form =~ s/\$\((\w+)\)/$data{$1}/ge;

    $form = _gen_header($self, 'NOTIFY', $form);
    $sock->send($form);
    my $ret = '';
    while (<$sock>) {
        $_ =~ s!\r\n!!g;
        print "$_\n" if $self->{Debug};
        $ret  = $1 if $_ =~ /^GNTP\/1.0 -(\w+).*$/;
        last if length($_) == 0;
    }
    if ($ret eq 'OK' && $data{CallbackContext} && $data{CallbackContextType}) {
        push @{$self->{Callbacks}}, {
            AppName  => $self->{AppName},
            Socket   => $sock,
            Function => $data{CallbackFunction},
        };
    } else {
        close $sock;
    }
    return $ret eq 'OK';
}

sub subscribe {
    my ( $self, %args ) = @_;
    chomp(my $hostname = `hostname`);
    my %data = (
        ID                  => $args{ID} || Data::UUID->new->create_str,
        Name                => $args{Name} || $hostname,
        Port                => $args{Port} || 23053,
    );
    $data{$_} =~ s!\r\n!\n! for ( keys %data );
    my $password = $args{Password} || '';
    my $callback = $args{CallbackFunction} || '';

    my $sock = IO::Socket::INET->new(
        PeerAddr => $self->{PeerHost},
        PeerPort => $self->{PeerPort},
        Proto    => $self->{Proto},
    );
    die $@ unless $sock;

    my $form = <<EOF;
Subscriber-ID: \$(ID)
Subscriber-Name: \$(Name)
Subscriber-Port: \$(Port)

EOF
    $form =~ s!\n!\r\n!g;
    $form =~ s/\$\((\w+)\)/$data{$1}/ge;

    $form = _gen_header($self, 'SUBSCRIBE', $form);
    $sock->send($form);
    my $ret = '';
    while (<$sock>) {
        $_ =~ s!\r\n!!g;
        print "$_\n" if $self->{Debug};
        $ret  = $1 if $_ =~ /^GNTP\/1.0 -(\w+).*$/;
        last if length($_) == 0;
    }
    close $sock;

    $sock = IO::Socket::INET->new(
        LocalPort => $data{Port},
        Proto => 'tcp',
        Listen => 10,
    );
    while (1) {
        my $client = $sock->accept();
        my ($Title, $Message) = ('', '');
        while (<$client>){
            $_ =~ s!\r\n!!g;
            print "$_\n" if $self->{Debug};
            $ret     = $1 if $_ =~ /^GNTP\/1.0 -(\w+).*/;
            $Title   = $1 if $_ =~ /^Notification-Title: (.*)\r\n/;
            $Message = $1 if $_ =~ /^Notification-Text: (.*)\r\n/;
            # TODO
            # handling more GNTP protocols. 
            # currently, can't treat multiline header which include LF.
            last if length($_) == 0;
        }
        $client->close();

        if ($Title && ref($callback) eq 'CODE') {
            $callback->($Title, $Message);
        }
    }
    return $ret eq 'OK';
}

sub wait {
    my $self = shift;
    my $waitall = shift || 1;

    my @callbacks = @{$self->{Callbacks}};
    my @old = @callbacks;
    my $bits = "";
    while (@callbacks) {
        vec($bits, fileno($_->{Socket}), 1) = 1 for @callbacks;
        next unless select($bits, undef, undef, 0.1);
        for (my $i = 0; $i < @callbacks; $i++) {
            my $callback = $callbacks[$i];
            my $sock = $callback->{Socket};
            if (vec($bits, fileno($sock), 1)) {
                my ($result, $type, $context) = ('', '', '');
                while (<$sock>) {
                    $_ =~ s!\r\n!!g;
                    print "$_\n" if $self->{Debug};
                    $result  = $1 if $_ =~ /^Notification-Callback-Result: (.*)$/;
                    $context = $1 if $_ =~ /^Notification-Callback-Context: (.*)$/;
                    $type    = $1 if $_ =~ /^Notification-Callback-Context-Type: (.*)$/;
                    last if length($_) == 0;
                }
                if (ref($callback->{Function}) eq 'CODE') {
                    $callback->{Function}->($result, $type, $context);
                }
                splice(@callbacks, $i, 1);
            }
        }
        last unless $waitall;
    };

    for (my $i = 0; $i < @{$self->{Callbacks}}; ++$i) {
        if (grep { $_->{Socket} eq $self->{Callbacks}[$i]->{Socket} } @old) {
            splice(@{$self->{Callbacks}}, $i--, 1);
        }
    }
    1;
}

sub _translate_int {
    return 0 + shift;
}

sub _translate_bool {
    my $value = shift;
    return 'True' if $value =~ /^([Tt]rue|[Yy]es)$/;
    return 'False' if $value =~ /^([Ff]alse|[Nn]o)$/;
    return 'True' if $value;
    return 'False';
}

sub _gen_header {
    my ($ctx, $method, $form) = @_;

    if ($ctx->{Password}) {
        my ($hash, $salt) = _gen_hash($ctx);
        my $crypt = _gen_encrypt($ctx, $salt, \$form);
        if ($crypt eq 'NONE') {
            $form = "GNTP/1.0 $method NONE $hash\r\n$form\r\n";
        } else {
            $form = "GNTP/1.0 $method $crypt $hash\r\n$form\r\n\r\n";
        }
    } else {
        $form = "GNTP/1.0 $method NONE\r\n$form\r\n";
    }
    return $form;
}

sub _gen_salt {
    my $count = shift;
    my @salt = ( '.', '/', 0 .. 9, 'A' .. 'Z', 'a' .. 'z' );
    my $salt;
    $salt .= (@salt)[rand @salt] for 1..$count;
    return $salt;
}

sub _gen_hash {
    my $ctx = shift;
    my $hash_algorithm = $ctx->{PasswordHashAlgorithm};
    my $password       = $ctx->{Password};
    return 'NONE' if $hash_algorithm eq 'NONE';

    my $salt = _gen_salt(8);
    my $salthex = uc unpack("H*", $salt);

    my %hashroll = (
        'MD5'    => sub { my ($password, $salt) = @_; return uc Digest::MD5::md5_hex(Digest::MD5->new->add($password)->add($salt)->digest); },
        'SHA1'   => sub { my ($password, $salt) = @_; return uc Digest::SHA::sha1_hex(Digest::SHA->new(1)->add($password)->add($salt)->digest); },
        'SHA256' => sub { my ($password, $salt) = @_; return uc Digest::SHA::sha256_hex(Digest::SHA->new(256)->add($password)->add($salt)->digest); },
    );
    my $key = $hashroll{$hash_algorithm}->($password, $salt);
    return "$hash_algorithm:$key.$salthex", $salt;
}

sub _gen_encrypt {
    my ($ctx, $salt, $data) = @_;
    my $hash_algorithm  = $ctx->{PasswordHashAlgorithm};
    my $crypt_algorithm = $ctx->{EncryptAlgorithm};
    my $password        = $ctx->{Password};
    return 'NONE' if $crypt_algorithm eq 'NONE';

    my %hashroll = (
        'MD5'    => sub { my ($password, $salt) = @_; return Digest::MD5->new->add($password)->add($salt)->digest },
        'SHA1'   => sub { my ($password, $salt) = @_; return Digest::SHA->new(1)->add($password)->add($salt)->digest },
        'SHA256' => sub { my ($password, $salt) = @_; return Digest::SHA->new(256)->add($password)->add($salt)->digest },
    );
    my $key = $hashroll{$hash_algorithm}->($password, $salt);

    my %cryptroll = (
        'AES'  => sub {
            my ($data, $key) = @_;
            my $iv = Crypt::CBC->random_bytes(16);
            my $cbc = Crypt::CBC->new(
                -key => substr($key, 0, 24),
                -iv => $iv,
                -keysize => 24,
                -header => 'none',
                -literal_key => 1,
                -padding => 'standard',
                -cipher => 'Crypt::OpenSSL::AES',
            );
            return $cbc->encrypt($data), uc unpack("H*", $iv);
        },
        'DES'  => sub {
            my ($data, $key) = @_;
            my $iv = Crypt::CBC->random_bytes(8);
            my $cbc = Crypt::CBC->new(
                -key => substr($key, 0, 8),
                -iv => $iv,
                -header => 'none',
                -literal_key => 1,
                -padding => 'standard',
                -cipher => 'DES',
            );
            return $cbc->encrypt($data), uc unpack("H*", $iv);
        },
        '3DES' => sub {
            my ($data, $key) = @_;
            my $iv = Crypt::CBC->random_bytes(8);
            $key = $key.substr($key,0,24-length($key)) if length($key) < 24;
            my $cbc = Crypt::CBC->new(
                -key => substr($key, 0, 24),
                -iv => $iv,
                -header => 'none',
                -literal_key => 1,
                -padding => 'standard',
                -cipher => 'DES_EDE3',
            );
            return $cbc->encrypt($data), uc unpack("H*", $iv);
        },
    );
    ($$data, my $hash) = $cryptroll{$crypt_algorithm}->($$data, $key);
    return "$crypt_algorithm:$hash";
}

sub _debug {
    my ($name, $data) = @_;
    open my $f, ">", $name;
    binmode $f;
    print $f $data;
    close $f;
}

1;
__END__

=head1 NAME

Growl::GNTP - Perl implementation of GNTP Protocol (Client Part)

=head1 SYNOPSIS

  use Growl::GNTP;
  my $growl = Growl::GNTP->new(AppName => "my perl app");
  $growl->register([
      { Name => "foo", },
      { Name => "bar", },
  ]);
  
  $growl->notify(
      Event => "foo",
      Title => "my notify",
      Message => "my message",
      Icon => "http://www.example.com/my-face.png",
  );

=head1 DESCRIPTION

Growl::GNTP is Perl implementation of GNTP Protocol (Client Part)

=head1 CONSTRUCTOR

=over 4

=item new ( ARGS )

Initialize Growl::GNTP object. You can set few parameter of
IO::Socket::INET. and application name will be given 'Growl::GNTP' if you
does not specify it.

=back

=head1 OBJECT METHODS

=over 4

=item register ( [ARGS] )

Register notification definition. You should be specify ARRAY reference of
HASH reference like a following.

  {
      Name        => 'MY_GROWL_NOTIFY',
      DisplayName => 'My Growl Notify',
      Enabled     => 'True',
  }

=item notify ( ARGS )

Notify item. You should be specify HASH reference like a following.

  {
      Event               => 'Warn', # name of notification
      Title               => 'Foo!',
      Message             => 'Bar!',
      Icon                => 'http://www.example.com/myface.png',
      CallbackContextType => time, # type of the context
      CallbackContext     => 'Time',
      CallbackFunction    => sub { warn 'callback!' },
  }

And callback function is given few arguments.

    CallbackFunction => sub {
        my ($result, $type, $context) = @_;
        print "$result: $context ($type)\n";
    }

=item wait ( WAIT_ALL )

Wait callback items. If WAIT_ALL is not 0, this function wait all callbacks
as CLICK, CLOSED, TIMEOUT.

=item subscribe ( ARGS )

Subscribe notification. You should be specify HASH reference like a following.

    {
        Port => 23054,
        Password => 'secret',
        CallbackFunction => sub {
            my ($Title, $Message) = @_;
            print decode_utf8($Title),",",decode_utf8($Message),"\n";
        },
    }

=back

=head1 AUTHOR

Yasuhiro Matsumoto E<lt>mattn.jp@gmail.comE<gt>

=head1 SEE ALSO

L<Net::Growl>, L<Net::GrowlClient>, L<Mac::Growl>,
F<http://www.growlforwindows.com/gfw/help/gntp.aspx>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut


