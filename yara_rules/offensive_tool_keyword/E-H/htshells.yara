rule htshells
{
    meta:
        description = "Detection patterns for the tool 'htshells' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htshells"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string1 = /.{0,1000}\sprepare\.sh\sshell\/mod_.{0,1000}\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string2 = /.{0,1000}\/htshells\.git.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string3 = /.{0,1000}\/prepare\.sh\sshell\/mod_.{0,1000}\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string4 = /.{0,1000}htshells\-master.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string5 = /.{0,1000}http:\/\/.{0,1000}\/\.htaccess\?c\=cmd.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string6 = /.{0,1000}http:\/\/.{0,1000}\/\.htaccess\?c\=uname\s\-a.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string7 = /.{0,1000}https:\/\/.{0,1000}\/\.htaccess\?c\=cmd.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string8 = /.{0,1000}https:\/\/.{0,1000}\/\.htaccess\?c\=uname\s\-a.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string9 = /.{0,1000}mod_auth_remote\.phish\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string10 = /.{0,1000}mod_caucho\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string11 = /.{0,1000}mod_cgi\.shell\.bash\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string12 = /.{0,1000}mod_cgi\.shell\.bind\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string13 = /.{0,1000}mod_cgi\.shell\.windows\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string14 = /.{0,1000}mod_mono\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string15 = /.{0,1000}mod_multi\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string16 = /.{0,1000}mod_perl\.embperl\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string17 = /.{0,1000}mod_perl\.IPP\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string18 = /.{0,1000}mod_perl\.Mason\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string19 = /.{0,1000}mod_perl\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string20 = /.{0,1000}mod_php\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string21 = /.{0,1000}mod_php\.shell2\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string22 = /.{0,1000}mod_php\.stealth\-shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string23 = /.{0,1000}mod_python\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string24 = /.{0,1000}mod_rivet\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string25 = /.{0,1000}mod_ruby\.shell\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string26 = /.{0,1000}mod_sendmail\.rce\.htaccess.{0,1000}/ nocase ascii wide
        // Description: Self contained htaccess shells and attacks
        // Reference: https://github.com/wireghoul/htshells
        $string27 = /.{0,1000}wireghoul\/htshells.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
