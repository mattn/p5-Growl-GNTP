use inc::Module::Install;
name 'Net-Growl-GNTP';
all_from 'lib/Net/Growl/GNTP.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
use_test_base;
auto_include;
WriteAll;
