
use strict;
use warnings;

use ExtUtils::MakeMaker;
use Alien::Sodium;
use File::Spec ();
use File::ShareDir ();
use Config;
use Text::ParseWords qw(shellwords);

my $lib_ext = $Config{lib_ext};

my $libsodium = Alien::Sodium->new;

my $libsodium_lib = "libsodium${lib_ext}";
my $libsodium_path;
my @dirs = map { s/^-L//g; $_ } grep { /^-L/ } shellwords($libsodium->libs);

# pkg-config may fail, so try harder to locate libsodium.a
push @dirs, File::Spec->catdir( File::ShareDir::dist_dir("Alien-Sodium"), 'lib' );

for my $dir ( @dirs ) {
    if ( -e "$dir/libsodium${lib_ext}" ) {
        $libsodium_path = "$dir/$libsodium_lib";
        last;
    }
}

die "Is Alien::Sodium available? Could not locate $libsodium_lib in @dirs\n"
    unless $libsodium_path;

my %WriteMakefileArgs = (
  ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Crypt/NaCl/Sodium.pm', # retrieve abstract from module
       AUTHOR         => "Alex J. G. Burzy\x{144}ski <ajgb\@cpan.org>") : ()),
  "BUILD_REQUIRES" => {
    "ExtUtils::CBuilder" => 0,
  },
  "CONFIGURE_REQUIRES" => {
    "File::ShareDir" => 0,
    "File::Spec" => 0,
    "Alien::Sodium" => "1.0.3.0",
    "ExtUtils::MakeMaker" => "0",
    "ExtUtils::CBuilder" => 0,
  },
  "DISTNAME" => "Crypt-NaCl-Sodium",
  "EXE_FILES" => [],
  "MYEXTLIB"  => $libsodium_path,
  "INC"       => join(' ', "-I.", $libsodium->cflags),
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



