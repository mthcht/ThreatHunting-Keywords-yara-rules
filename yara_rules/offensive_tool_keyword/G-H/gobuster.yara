rule gobuster
{
    meta:
        description = "Detection patterns for the tool 'gobuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gobuster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string1 = /\/gobuster\.git/
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string2 = "/gobuster/"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string3 = "/gobusterdir/"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string4 = "/gobusterdns/"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string5 = "/gobustergcs/"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string6 = "/libgobuster"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string7 = "/OJ/gobuster"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string8 = "gobuster dir "
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string9 = "gobuster dns"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string10 = "gobuster fuzz -"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string11 = "gobuster gcs "
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string12 = "gobuster s3 "
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string13 = "gobuster tftp "
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string14 = "gobuster vhost -u "
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string15 = "gobuster vhost"
        // Description: Gobuster is a tool used to brute-force
        // Reference: https://github.com/OJ/gobuster
        $string16 = "gobuster"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string17 = /gobuster_.{0,1000}\.tar\.gz/
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string18 = /gobuster_.{0,1000}\.zip/
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string19 = "gobusterfuzz"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string20 = "gobustertftp"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string21 = "install gobuster"
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string22 = /\-w\s.{0,1000}wordlists.{0,1000}\.txt/

    condition:
        any of them
}
