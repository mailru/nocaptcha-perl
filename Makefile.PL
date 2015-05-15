use 5.010001;
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'Captcha::Nocaptcha',
    VERSION_FROM      => 'lib/Captcha/Nocaptcha.pm',
    PREREQ_PM         => {
        LWP::UserAgent => 5,
        JSON => 2,
        URI::Escape => 3,
    },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Captcha/Nocaptcha.pm', # retrieve abstract from module
       AUTHOR         => 'Oleg Kovalev <man0xff@gmail.com>') : ()),
);
