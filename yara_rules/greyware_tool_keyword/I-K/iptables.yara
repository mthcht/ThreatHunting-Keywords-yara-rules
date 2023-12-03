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
        $string1 = /chkconfig\soff\sip6tables/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string2 = /chkconfig\soff\siptables/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string3 = /service\sip6tables\sstop/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string4 = /service\siptables\sstop/ nocase ascii wide

    condition:
        any of them
}
