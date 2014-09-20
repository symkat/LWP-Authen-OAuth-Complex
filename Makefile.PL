use inc::Module::Install;

name            'LWP-Authen-OAuth-Complex';
all_from        'lib/LWP/Authen/OAuth/Complex';
license         'perl';

requires        'LWP::UserAgent'        => '0';

WriteAll;
