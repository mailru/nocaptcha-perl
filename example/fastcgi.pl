use Captcha::Nocaptcha;
use FCGI;
use Data::Dumper;
use URI::Escape;

use constant PUBLIC_KEY => 'e5238532bf56e4c24bd5489d463ac2a0';
use constant PRIVATE_KEY => '3cf11185476394b85bcec3fbf16c69a4';

sub unpack_params {
    my ($buf, %params);
    read(STDIN, $buf, $ENV{'CONTENT_LENGTH'});
    my @pairs = split(/&/, $buf);
    foreach my $pair (@pairs) {
        my ($key, $val) = split(/=/, $pair);
        $key = uri_unescape($key);
        $val = uri_unescape($val);
        $params{$key} = $val;
    }
    return \%params;
}

my $sock = FCGI::OpenSocket(":9000", 5);
my $req = FCGI::Request(\*STDIN, \*STDOUT, \*STDOUT, \%ENV, $sock);

while ($req->Accept() >= 0) {
    if ($ENV{REQUEST_METHOD} eq "POST") {
        my $params = unpack_params();
        my $res = Dumper(nocaptcha_check_detailed(PRIVATE_KEY, $params->{captcha_id}, $params->{captcha_value}));
        print("Content-Type: text/html\r\n\r\n");
        print <<"            END";
            <html>
                <head></head>
                <body>
                    <p>result: '$res', <a href="">try again</a></p>
                </body>
            </html>
            END
    }
    else {
        my $script = nocaptcha_generate_captcha_tag(PUBLIC_KEY);
        print("Content-Type: text/html\r\n\r\n");
        print <<"            END";
            <html>
                <head>
                    $script
                </head>
                <body>
                    <form action="#" method="POST">
                        <p>text<br><input type="text" name="text" size="30"></p>
                        <p><div id="nocaptcha"></div></p>
                        <p><input type="submit" value="submit"></p>
                    </form>
                </body>
            </html>
            END
    }
}
