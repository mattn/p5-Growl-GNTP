use inc::Module::Install;
name 'Net-Growl-GNTP';
all_from 'lib/Net/Growl/GNTP.pm';

requires 'Data::UUID'  => 0.149;
requires 'Crypt::CBC'  => 2.29;
requires 'Digest::MD5' => 2.36;
requires 'Digest::SHA' => 5.45;

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
use_test_base;
auto_include;
WriteAll;
