requires 'Crypt::CBC', '2.29';
requires 'Data::UUID', '0.149';
requires 'Digest::MD5', '2.36';
requires 'Digest::SHA', '5.45';
requires 'Filter::Util::Call';
requires 'IO::Socket::PortState';

on configure => sub {
    requires 'Module::Build::Tiny';
};

on build => sub {
    requires 'ExtUtils::MakeMaker', '6.36';
};
