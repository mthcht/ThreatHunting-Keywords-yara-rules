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
        $string1 = /.{0,1000}\/gobuster\.git.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string2 = /.{0,1000}\/gobuster\/.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string3 = /.{0,1000}\/gobusterdir\/.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string4 = /.{0,1000}\/gobusterdns\/.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string5 = /.{0,1000}\/gobustergcs\/.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string6 = /.{0,1000}\/libgobuster.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string7 = /.{0,1000}\/OJ\/gobuster.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string8 = /.{0,1000}gobuster\sdir\s.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string9 = /.{0,1000}gobuster\sdns.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string10 = /.{0,1000}gobuster\sfuzz\s\-.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string11 = /.{0,1000}gobuster\sgcs\s.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string12 = /.{0,1000}gobuster\ss3\s.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string13 = /.{0,1000}gobuster\stftp\s.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string14 = /.{0,1000}gobuster\svhost\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string15 = /.{0,1000}gobuster\svhost.{0,1000}/ nocase ascii wide
        // Description: Gobuster is a tool used to brute-force
        // Reference: https://github.com/OJ/gobuster
        $string16 = /.{0,1000}gobuster.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string17 = /.{0,1000}gobuster_.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string18 = /.{0,1000}gobuster_.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string19 = /.{0,1000}gobusterfuzz.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string20 = /.{0,1000}gobustertftp.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string21 = /.{0,1000}install\sgobuster.{0,1000}/ nocase ascii wide
        // Description: Directory/File DNS and VHost busting tool written in Go
        // Reference: https://github.com/OJ/gobuster
        $string22 = /.{0,1000}\-w\s.{0,1000}wordlists.{0,1000}\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
