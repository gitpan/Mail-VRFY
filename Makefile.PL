use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'           => 'Mail::VRFY',
    'VERSION_FROM'   => 'VRFY.pm', # finds $VERSION
    'PREREQ_PM'      => {Net::DNS => 0.46, IO::Socket::INET => 1.0, Sys::Hostname => 1.0, IO::Select => 1.13},
    ($] >= 5.005 ?
      (ABSTRACT_FROM => 'VRFY.pm',
       AUTHOR        => 'Jeremy Kister <http://jeremy.kister.net/>') : ()),
);
