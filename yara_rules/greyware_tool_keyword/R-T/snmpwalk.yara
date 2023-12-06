rule snmpwalk
{
    meta:
        description = "Detection patterns for the tool 'snmpwalk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpwalk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: allows you to enumerate the SNMP devices and places the output in a very human readable friendly format
        // Reference: https://wiki.debian.org/SNMP
        $string1 = /snmpwalk\s\s\-v1\s\-cpublic\s/ nocase ascii wide
        // Description: allows you to enumerate the SNMP devices and places the output in a very human readable friendly format
        // Reference: https://wiki.debian.org/SNMP
        $string2 = /snmpwalk\s.{0,1000}\spublic\s.{0,1000}1\.3\.6\.1\./ nocase ascii wide
        // Description: allows you to enumerate the SNMP devices and places the output in a very human readable friendly format
        // Reference: https://wiki.debian.org/SNMP
        $string3 = /snmpwalk\s\-c\spublic\s\-v1\s/ nocase ascii wide

    condition:
        any of them
}
