#!/usr/bin/perl
use warnings;
use strict;
use LWP::Authen::OAuth::Complex;

my $ua = LWP::Authen::OAuth::Complex->new();

$ua->post( "http://google.com/?foo=baf", [ 
        'b5'                    => "=%3D",
        'a3'                    => "a",
        'c@'                    => "",
        'a2'                    => 'r b',
        oauth_consumer_key      => '9djdj82h48djs9d2',
        oauth_token             => 'kkk9d7dh3k39sjv7',
        oauth_signature_method  => 'HMAC-SHA1',
        oauth_timestamp         => '137131201',
        oauth_nonce             => '7d8f3e4a',
        c2                      => "",
        a3                      => '2 q',
    ], 
);



print "Hello World\n";
