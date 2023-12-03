rule systemctl
{
    meta:
        description = "Detection patterns for the tool 'systemctl' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "systemctl"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string1 = /.{0,1000}systemctl\sdisable\scbdaemon.{0,1000}/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string2 = /.{0,1000}systemctl\sdisable\sfalcon\-sensor\.service.{0,1000}/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string3 = /.{0,1000}systemctl\sstop\scbdaemon.{0,1000}/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string4 = /.{0,1000}systemctl\sstop\sfalcon\-sensor\.service.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
