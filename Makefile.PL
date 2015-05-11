
use strict;
use warnings;

use ExtUtils::MakeMaker;
use Alien::Sodium;

my $libsodium = Alien::Sodium->new;

my $cflags = $libsodium->cflags;
my $libs   = $libsodium->libs;

$libs =~ s/ -lsodium//g;
$libs .= ' -Wl,-Bstatic -l:libsodium.a -Wl,-Bdynamic';

my %WriteMakefileArgs = (
  ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Crypt/NaCl/Sodium.pm', # retrieve abstract from module
       AUTHOR         => 'Alex J. G. Burzyński <ajgb\@cpan.org>') : ()),
  "BUILD_REQUIRES" => {
    "ExtUtils::CBuilder" => 0,
  },
  "CONFIGURE_REQUIRES" => {
    "Alien::Sodium" => "1.0.3.0",
    "ExtUtils::MakeMaker" => "0",
    "ExtUtils::CBuilder" => 0,
  },
  "DISTNAME" => "Crypt-NaCl-Sodium",
  "EXE_FILES" => [],
  "LIBS"      => [$libs],
  "INC"       => join(' ', "-I.", $cflags),
  "LICENSE" => "perl",
  "NAME" => "Crypt::NaCl::Sodium",
  "PREREQ_PM" => {
    "Alien::Sodium" => '1.0.3.0',
    "Carp" => 0,
    "Sub::Exporter" => 0,
    "XSLoader" => 0,
    "strict" => 0,
    "warnings" => 0
  },
  "TEST_REQUIRES" => {
    "Test::More" => 0,
  },
  "VERSION_FROM"     => 'lib/Crypt/NaCl/Sodium.pm',
  "test" => {
    "TESTS" => "t/*.t"
  }
);

my %FallbackPrereqs = (
  "Alien::Sodium" => "1.0.3.0",
  "Carp" => 0,
  "Sub::Exporter" => 0,
  "Test::More" => 0,
  "XSLoader" => 0,
  "strict" => 0,
  "warnings" => 0
);

unless ( eval { ExtUtils::MakeMaker->VERSION(6.63_03) } ) {
  delete $WriteMakefileArgs{TEST_REQUIRES};
  delete $WriteMakefileArgs{BUILD_REQUIRES};
  $WriteMakefileArgs{PREREQ_PM} = \%FallbackPrereqs;
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);



