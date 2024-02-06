rule sshx
{
    meta:
        description = "Detection patterns for the tool 'sshx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshx"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string1 = /\s\-\-bin\ssshx\-server/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string2 = /\ss3\:\/\/sshx\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string3 = /\.vm\.sshx\.internal\:8051/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string4 = /\/release\/sshx\-server/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string5 = /\/sshx\-server\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string6 = /\\sshx\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string7 = /cargo\sinstall\ssshx/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string8 = /ekzhang\/sshx/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string9 = /https\:\/\/s3\.amazonaws\.com\/sshx\/sshx\-/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string10 = /https\:\/\/sshx\.io\/get/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string11 = /https\:\/\/sshx\.io\/s\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string12 = /sshx\-server\s\-\-listen/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string13 = /sshx\-server\-.{0,1000}\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}
