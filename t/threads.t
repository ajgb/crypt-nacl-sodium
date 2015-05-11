
use strict;
use warnings;
use Test::More;
use Config;

BEGIN {
    plan skip_all => 'Perl compiled without ithreads'
        unless $Config{useithreads};
}


use threads;

use Crypt::NaCl::Sodium qw( :utils );

{
    my $crypto_generichash = Crypt::NaCl::Sodium->generichash;
    my $key = $crypto_generichash->keygen( $crypto_generichash->KEYBYTES_MAX );
    my $hasher = $crypto_generichash->init(
        bytes => $crypto_generichash->BYTES_MAX,
        key => $key
    );
    $hasher->update("foo");

    my $tdigest = threads->create(sub { $hasher->update("bar"); $hasher->final })->join;

    isnt $hasher->clone->final->to_hex, $tdigest->to_hex, "unshared object unaffected by the thread";

    $hasher->update("bar");
    is $hasher->clone->final->to_hex, $tdigest->to_hex, "final mac matches";
}
{
    my $crypto_hash = Crypt::NaCl::Sodium->hash;
    my $hasher = $crypto_hash->sha256_init();
    $hasher->update("foo");

    my $tdigest = threads->create(sub { $hasher->update("bar"); $hasher->final })->join;

    isnt $hasher->clone->final->to_hex, $tdigest->to_hex, "unshared object unaffected by the thread";

    $hasher->update("bar");
    is $hasher->clone->final->to_hex, $tdigest->to_hex, "final mac matches";
}
{
    my $crypto_hash = Crypt::NaCl::Sodium->hash;
    my $hasher = $crypto_hash->sha512_init();
    $hasher->update("foo");

    my $tdigest = threads->create(sub { $hasher->update("bar"); $hasher->final })->join;

    isnt $hasher->clone->final->to_hex, $tdigest->to_hex, "unshared object unaffected by the thread";

    $hasher->update("bar");
    is $hasher->clone->final->to_hex, $tdigest->to_hex, "final mac matches";
}
{
    my $crypto_auth = Crypt::NaCl::Sodium->auth;
    my $key = $crypto_auth->keygen;
    my $hasher = $crypto_auth->hmacsha256_init($key);
    $hasher->update("foo");

    my $tdigest = threads->create(sub { $hasher->update("bar"); $hasher->final })->join;

    isnt $hasher->clone->final->to_hex, $tdigest->to_hex, "unshared object unaffected by the thread";

    $hasher->update("bar");
    is $hasher->clone->final->to_hex, $tdigest->to_hex, "final mac matches";
}
{
    my $crypto_auth = Crypt::NaCl::Sodium->auth;
    my $key = $crypto_auth->keygen;
    my $hasher = $crypto_auth->hmacsha512_init($key);
    $hasher->update("foo");

    my $tdigest = threads->create(sub { $hasher->update("bar"); $hasher->final })->join;

    isnt $hasher->clone->final->to_hex, $tdigest->to_hex, "unshared object unaffected by the thread";

    $hasher->update("bar");
    is $hasher->clone->final->to_hex, $tdigest->to_hex, "final mac matches";
}
{
    my $crypto_auth = Crypt::NaCl::Sodium->auth;
    my $key = $crypto_auth->keygen;
    my $hasher = $crypto_auth->hmacsha512256_init($key);
    $hasher->update("foo");

    my $tdigest = threads->create(sub { $hasher->update("bar"); $hasher->final })->join;

    isnt $hasher->clone->final->to_hex, $tdigest->to_hex, "unshared object unaffected by the thread";

    $hasher->update("bar");
    is $hasher->clone->final->to_hex, $tdigest->to_hex, "final mac matches";
}
{
    my $crypto_onetimeauth = Crypt::NaCl::Sodium->onetimeauth;
    my $key = $crypto_onetimeauth->keygen;
    my $hasher = $crypto_onetimeauth->init($key);
    $hasher->update("foo");

    my $tdigest = threads->create(sub { $hasher->update("bar"); $hasher->final })->join;

    isnt $hasher->clone->final->to_hex, $tdigest->to_hex, "unshared object unaffected by the thread";

    $hasher->update("bar");
    is $hasher->clone->final->to_hex, $tdigest->to_hex, "final mac matches";
}

done_testing();

