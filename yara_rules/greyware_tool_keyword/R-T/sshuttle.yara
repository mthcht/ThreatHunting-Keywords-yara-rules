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
        $string1 = " install sshuttle"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string2 = " py39-sshuttle"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string3 = " sshuttle:sshuttle "
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string4 = "/etc/sshuttle"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string5 = "/home/sshuttle"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string6 = /\/sshuttle\.git/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string7 = /\/sshuttle\.py/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string8 = "/sshuttle/tarball"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string9 = "/sshuttle/zipball"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string10 = "/tmp/sshuttle"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string11 = "b86e9468c1470e3a3e776f5cab91a1cb79927743cfbc92535e753024611e8b4e" nocase ascii wide
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string12 = "net-proxy/sshuttle"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string13 = "sshuttle -"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string14 = /sshuttle\.cmdline/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string15 = /sshuttle\.firewall/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string16 = /sshuttle\.linux/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string17 = /sshuttle\.methods\.socket/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string18 = /sshuttle\.server/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string19 = /sshuttle\.service/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string20 = /sshuttle\.ssh/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string21 = "sshuttle/sshuttle"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string22 = "SSHUTTLE0001"
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string23 = /sudoers\.d\/sshuttle_auto/
        // Description: Transparent proxy server that works as a poor man's VPN. Forwards over ssh
        // Reference: https://github.com/sshuttle/sshuttle
        $string24 = "systemctl start sshuttle"

    condition:
        any of them
}
