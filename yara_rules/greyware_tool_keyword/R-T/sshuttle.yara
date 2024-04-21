rule sshuttle
{
    meta:
        description = "Detection patterns for the tool 'sshuttle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshuttle"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string1 = /\sinstall\ssshuttle/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string2 = /\spy39\-sshuttle/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string3 = /\ssshuttle\:sshuttle\s/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string4 = /\/etc\/sshuttle/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string5 = /\/home\/sshuttle/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string6 = /\/sshuttle\.git/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string7 = /\/sshuttle\.py/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string8 = /\/sshuttle\/tarball/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string9 = /\/sshuttle\/zipball/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string10 = /\/tmp\/sshuttle/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string11 = /b86e9468c1470e3a3e776f5cab91a1cb79927743cfbc92535e753024611e8b4e/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string12 = /net\-proxy\/sshuttle/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string13 = /sshuttle\s\-/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string14 = /sshuttle\.cmdline/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string15 = /sshuttle\.firewall/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string16 = /sshuttle\.linux/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string17 = /sshuttle\.methods\.socket/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string18 = /sshuttle\.server/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string19 = /sshuttle\.service/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string20 = /sshuttle\.ssh/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string21 = /sshuttle\/sshuttle/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string22 = /SSHUTTLE0001/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string23 = /sudoers\.d\/sshuttle_auto/ nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string24 = /systemctl\sstart\ssshuttle/ nocase ascii wide

    condition:
        any of them
}
