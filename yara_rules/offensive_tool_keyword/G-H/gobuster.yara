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
        $string1 = /\/gobuster\.git/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string2 = "/gobuster/" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string3 = "/gobusterdir/" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string4 = "/gobusterdns/" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string5 = "/gobustergcs/" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string6 = "/libgobuster" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string7 = "/OJ/gobuster" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string8 = "gobuster dir " nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string9 = "gobuster dns" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string10 = "gobuster fuzz -" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string11 = "gobuster gcs " nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string12 = "gobuster s3 " nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string13 = "gobuster tftp " nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string14 = "gobuster vhost -u " nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string15 = "gobuster vhost" nocase ascii wide
        // Description: Gobuster is a tool used to brute-force
        // Reference: https://github.com/OJ/gobuster
        $string16 = "gobuster" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string17 = /gobuster_.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string18 = /gobuster_.{0,1000}\.zip/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string19 = "gobusterfuzz" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string20 = "gobustertftp" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string21 = "install gobuster" nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string22 = /\-w\s.{0,1000}wordlists.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}
