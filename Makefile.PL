use inc::Module::Install;

name            'LWP-Authen-OAuth-Complex';
all_from        'lib/LWP/Authen/OAuth/Complex.pm';
license         'perl';

requires        'LWP::UserAgent'        => '0';
requires        'URI::Encode'           => '0';

WriteAll;
