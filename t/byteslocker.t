
use strict;
use warnings;
use Test::More;

use Crypt::NaCl::Sodium qw(:utils);

$Data::BytesLocker::DEFAULT_LOCKED = 1;

my $crypto_secretbox = Crypt::NaCl::Sodium->secretbox();

for my $i ( 1 .. 2 ) {
    my $key = $crypto_secretbox->keygen();
    isa_ok($key, "Data::BytesLocker");
    ok($key->is_locked, "locked by default");
    eval {
        my $skey = "$key";
    };
    like($@, qr/^Unlock BytesLocker object before accessing the data/, "cannot access locked bytes");

    ok($key->unlock, "...but can unlock");

    like($key->to_hex, qr/^[a-f0-9]{64}$/, "->to_hex");
    my $skey = $key;
    isa_ok($skey, "Data::BytesLocker");

    eval { $key lt $skey ? 1 : 0 };
    like($@, qr/Operation "lt" is not supported/, 'Operation "lt" is not supported');
    eval { $key le $skey ? 1 : 0 };
    like($@, qr/Operation "le" is not supported/, 'Operation "le" is not supported');

    eval { $key gt $skey ? 1 : 0 };
    like($@, qr/Operation "gt" is not supported/, 'Operation "gt" is not supported');
    eval { $key ge $skey ? 1 : 0 };
    like($@, qr/Operation "ge" is not supported/, 'Operation "ge" is not supported');

    eval { $key .= "aaa" };
    like($@, qr/Operation "=" is not supported/, 'Operation "=" is not supported');

    my $key_str = "$key";
    is($key_str, $key, "stringification works");
    is(ref $key_str, '', "stringified object is plain scalar");

    my $key_bytes = $key->bytes;
    is($key_str, $key_bytes, "->bytes returns protected bytes");
    is(ref $key_bytes, '', "...and is plain scalar");

    ok($key eq $skey, "key -eq skey");
    ok(! ( $key ne $skey), "key -ne skey");
    ok($key, "-bool key");


    my $key_aaa = $key . "aaa";
    isa_ok($key_aaa, "Data::BytesLocker");
    eval {
        my $skey = "$key_aaa";
    };
    like($@, qr/^Unlock BytesLocker object before accessing the data/, "concat result locked");
    ok($key_aaa->unlock, "...but can unlock");

    is($key_aaa, "${key_str}aaa", "key . STR");

    my $aaa_key = "aaa" . $key;
    isa_ok($aaa_key, "Data::BytesLocker");
    eval {
        my $skey = "$aaa_key";
    };
    like($@, qr/^Unlock BytesLocker object before accessing the data/, "concat result locked");
    ok($aaa_key->unlock, "...but can unlock");

    is($aaa_key, "aaa${key_str}", "STR . key");

    my $key_x_5 = $key x 5;
    isa_ok($key_x_5, "Data::BytesLocker");
    eval {
        my $skey = "$key_x_5";
    };
    like($@, qr/^Unlock BytesLocker object before accessing the data/, "concat result locked");
    ok($key_x_5->unlock, "...but can unlock");

    is($key_x_5, "${key_str}${key_str}${key_str}${key_str}${key_str}", "key x 5");

    $key = "1234";

    ok(! ref $key, "key after assignment not longer an object");
}

my $locker1 = Data::BytesLocker->new("readonly protected data");
isa_ok($locker1, "Data::BytesLocker");
eval {
    my $s = "$locker1";
};
like($@, qr/^Unlock BytesLocker object before accessing the data/, "cannot access locked bytes");
ok($locker1->unlock, "...but can unlock");
is($locker1->to_hex, bin2hex("readonly protected data"), "->to_hex eq bin2hex");

eval {
    my $locker2 = Data::BytesLocker->new("readonly protected data", wipe => 1 );
};
like($@, qr/^Modification of a read-only value attempted/, "Cannot wipe readonly data");

my $var = "protected data";
my $var_len = length($var);
my $locker3 = Data::BytesLocker->new($var, wipe => 1 );
isa_ok($locker3, "Data::BytesLocker");
eval {
    my $s = "$locker3";
};
like($@, qr/^Unlock BytesLocker object before accessing the data/, "cannot access locked bytes");
ok($locker3->unlock, "...but can unlock");
is($locker3->to_hex, bin2hex("protected data"), "->to_hex eq bin2hex");
is($var, "\x0" x $var_len, "orginal variable wiped out");
is($locker3->length, $var_len, "->length works");

{
    $Data::BytesLocker::DEFAULT_LOCKED = 0;

    my $unlocked = Data::BytesLocker->new("not locked");
    ok(! $unlocked->is_locked, "not locked by default");
    is($unlocked, "not locked", "...and can be accessed");
    ok($unlocked->lock, "...but can be locked");
    eval {
        my $str = "$unlocked";
    };
    like($@, qr/^Unlock BytesLocker object before accessing the data/, "cannot access locked bytes");
}
{
    local $Data::BytesLocker::DEFAULT_LOCKED = 1;

    my $locked = Data::BytesLocker->new("is locked");
    ok($locked->is_locked, "now locked by default");
    eval {
        my $str = "$locked";
    };
    like($@, qr/^Unlock BytesLocker object before accessing the data/, "cannot access locked bytes");
    ok($locked->unlock, "...but can be unlocked");
    is($locked, "is locked", "...and can be accessed");
}
{
    my $unlocked = Data::BytesLocker->new("fall back to not locked");
    ok(! $unlocked->is_locked, "fall back to not locked by default");
    is($unlocked, "fall back to not locked", "...and can be accessed");
    ok($unlocked->lock, "...but can be locked");
    eval {
        my $str = "$unlocked";
    };
    like($@, qr/^Unlock BytesLocker object before accessing the data/, "cannot access locked bytes");
}

done_testing();

