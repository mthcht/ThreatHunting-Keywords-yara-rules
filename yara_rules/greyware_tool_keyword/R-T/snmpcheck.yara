rule snmpcheck
{
    meta:
        description = "Detection patterns for the tool 'snmpcheck' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpcheck"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: automate the process of gathering information of any devices with SNMP protocol support. like snmpwalk - snmpcheck allows you to enumerate the SNMP devices and places the output in a very human readable friendly format. It could be useful for penetration testing or systems monitoring
        // Reference: http://www.nothink.org/codes/snmpcheck/index.php
        $string1 = /install\ssnmpcheck/ nocase ascii wide
        // Description: automate the process of gathering information of any devices with SNMP protocol support. like snmpwalk - snmpcheck allows you to enumerate the SNMP devices and places the output in a very human readable friendly format. It could be useful for penetration testing or systems monitoring
        // Reference: http://www.nothink.org/codes/snmpcheck/index.php
        $string2 = /snmp\-check\s.{0,1000}\s\-c\spublic/ nocase ascii wide

    condition:
        any of them
}
