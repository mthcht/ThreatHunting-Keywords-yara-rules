rule iptables
{
    meta:
        description = "Detection patterns for the tool 'iptables' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iptables"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string1 = "chkconfig off ip6tables" nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string2 = "chkconfig off iptables" nocase ascii wide
        // Description: iptables to block syslog forwarding
        // Reference: https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day?hl=en
        $string3 = "iptables -A OUTPUT -p tcp --dport 514 -j DROP"
        // Description: iptables to block syslog forwarding
        // Reference: https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day?hl=en
        $string4 = "iptables -A OUTPUT -p tcp --dport 6514 -j DROP"
        // Description: iptables to block syslog forwarding
        // Reference: https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day?hl=en
        $string5 = "iptables -A OUTPUT -p udp --dport 514 -j DROP"
        // Description: iptables to block syslog forwarding
        // Reference: https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day?hl=en
        $string6 = "iptables -A OUTPUT -p udp --dport 6514 -j DROP"
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string7 = "service ip6tables stop" nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string8 = "service iptables stop" nocase ascii wide

    condition:
        any of them
}
