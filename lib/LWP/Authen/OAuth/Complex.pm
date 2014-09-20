package LWP::Authen::OAuth::Complex;
use warnings;
use strict;
use parent 'LWP::UserAgent';
use Carp qw( croak );
use URI::Encode qw( uri_encode );
use Data::Dumper;
use MIME::Base64 qw( encode_base64 );
use Digest::SHA qw( hmac_sha1 );

our $VERSION = '0.000100'; # 0.1.0
$VERSION = eval $VERSION;


sub new {
    my $class = shift;
    my $self  = ( ref $_[0] ? ( shift ) : ( { @_ } ) );

    my $opts = {
        oauth_consumer_key    => delete $self->{oauth_consumer_key},
        oauth_consumer_secret => delete $self->{oauth_consumer_secret},
        oauth_token           => delete $self->{oauth_token},
        oauth_token_secret    => delete $self->{oauth_token_secret},
    };

    $self = $class->SUPER::new( %{ $self } );

    for my $opt ( keys %$opts ) {
        $self->$opt( delete $opts->{$opt} );
    }

    return $self;
}

sub oauth_consumer_key {
    my $self = shift;
    $self->{oauth_consumer_key} = shift if @_;
    return $self->{oauth_consumer_key};
} 

sub oauth_consumer_secret {
    my $self = shift;
    $self->{oauth_consumer_secret} = shift if @_;
    return $self->{oauth_consumer_secret};
}

sub oauth_token {
    my $self = shift;
    $self->{oauth_token} = shift if @_;
    return $self->{oauth_token};
}

sub oauth_token_secret {
    my $self = shift;
    $self->{oauth_token_secret} = shift if @_;
    return $self->{oauth_token_secret};
}

sub oauth_verifier {
    my $self = shift;
    $self->{oauth_verifier} = shift if @_;
    return $self->{oauth_verifier};
}

sub oauth_nonce {
    my $self = shift;
    $self->{oauth_nonce} = shift if @_;
    return $self->{oauth_nonce};
}

sub oauth_signature_method {
    my $self = shift;

    if ( @_ ) {
        my $str = shift;
        if ( $str =~ /^(?:HMAC-SHA1|RSA-SHA1|PLAINTEXT)$/ ) {
            $self->{oauth_signature_method} = $str;
        } else {
            croak "Error: unrecognized argument ($str) to " .
            "oauth_signature_method (accepts HMAC-SHA1, RSA-SHA1, " .
            "and PLAINTEXT).";
        }
    }

    return $self->{oauth_signature_method} ||= "HMAC-SHA1";
}

sub oauth_fields {
    my ( $self ) = @_;

    return (
        [ oauth_nonce             => $self->oauth_nonce ],
        [ oauth_timestamp         => time ],
        [ oauth_version           => "1.0" ], # If not a string, this becomes 1
        ( $self->oauth_consumer_key ? [ oauth_consumer_key      => $self->oauth_consumer_key ] : () ),
        ( $self->oauth_token ? [ oauth_token             => $self->oauth_token ] : (  ) ),
        [ oauth_signature_method  => $self->oauth_signature_method ],
        ( $self->oauth_verifier ? [ oauth_verifier  => $self->oauth_verifier ] : (  ) ),
    );
}

sub request {
    my ( $self, $request, @args ) = @_;
    
    $self->set_oauth_nonce;

    $self->sign_request( $request );
    return $self->SUPER::request( $request, @args );

}

sub sign_request {
    my ( $self, $request ) = @_;
    
    my $sign = encode_base64( 
        hmac_sha1( $self->get_signature_base( $request ), $self->get_signing_key ) 
    );
    $request->header( "Authorization" => $self->get_authorization_header( $request, $sign)  );
}

sub get_authorization_header {
    my ( $self, $request, $signiture ) = @_;
    
    my @fields = ( ( map { sprintf( '%s="%s"', @{ $_ } ) } $self->oauth_fields ), 
        "oauth_signature=\"$signiture\"" );

    return "OAuth " . join( ", ", @fields );
}

sub get_signing_key {
    my ( $self ) = @_;

    return sprintf( 
        "%s&%s", 
        $self->oauth_consumer_secret,  
        ( $self->oauth_token_secret || "" ),
    );
}

sub get_signature_base {
    my ( $self, $request ) = @_;

    join( "&", 
        $self->oauth_encode($request->method), 
        $self->oauth_encode($request->uri), 
        $self->oauth_encode($self->normalize_request_params( $request )) 
    );
}
# Combine request params from the query and the request body 
# (in the instance of a URL encoded body)
sub normalize_request_params {
    my ( $self, $request ) = @_;
    
    my $uri = $request->uri->clone;
    my @query;
    # We COULD have a case of { foo => bar, foo => blee }, which
    # is allowed by the HTTP RFC.  We must treat each bit of the
    # query as its own key value pair to encode correctly.
    my @query_form = $uri->query_form;
    for ( my $i = 0; $i < @query_form ; $i += 2 ) {
        push @query, [
            $self->oauth_encode( $query_form[$i] ) => $self->oauth_encode($query_form[$i+1]),
        ];
    }

    if ( $request->header("Content-Type") eq 'application/x-www-form-urlencoded' ) {
        $uri->query( $request->content );
        my @query_form = $uri->query_form;
        for ( my $i = 0; $i < @query_form ; $i += 2 ) {
            push @query, [ 
                $self->oauth_encode( $query_form[$i] ) => $self->oauth_encode($query_form[$i+1]),
            ];
        }
    }

    push @query, $self->oauth_fields;

    @query = sort { $a->[0] cmp $b->[0] || $a->[1] cmp $b->[1] } @query;
    return join( "&", map { sprintf( "%s=%s", $_->[0], $_->[1] ) } @query );
}

sub set_oauth_nonce {
    shift->oauth_nonce(join "", map { sprintf( "%02x", int rand 255 ) } ( 1 .. 16 ));
}

sub sign {
    my ( $self, $request ) = @_;

}

sub oauth_encode {
    my ( $self, $str ) = @_;
    return "" unless $str;
    return uri_encode( $str, { encode_reserved => 1 } );
}

1;

=encoding UTF-8

=head1 NAME

LWP::Authen::OAuth::Complex - Configurable OAuth Client

=head1 DESCRIPTION

=head1 SYNOPSIS

=head1 AUTHOR

=over 4 

=item * Kaitlyn Parkhurst (SymKat) I<E<lt>symkat@symkat.comE<gt>> ( Blog: L<http://symkat.com/> )

=back

=head1 CONTRIBUTORS

=head1 COPYRIGHT AND LICENSE

This library is free software and may be distributed under the same terms
as perl itself.

=head1 AVAILABILITY

The latest version of this software is available at
L<https://github.com/symkat/LWP-Authen-OAuth-Complex>
