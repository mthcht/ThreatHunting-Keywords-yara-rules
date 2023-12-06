rule snmpwn
{
    meta:
        description = "Detection patterns for the tool 'snmpwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with Unknown user name when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do.
        // Reference: https://github.com/hatlord/snmpwn
        $string1 = /\/snmpwn\.git/ nocase ascii wide
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with Unknown user name when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do
        // Reference: https://github.com/hatlord/snmpwn
        $string2 = /\/snmpwn\.rb/ nocase ascii wide
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with  Unknown user name  when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do
        // Reference: https://github.com/hatlord/snmpwn
        $string3 = /hatlord\/snmpwn/ nocase ascii wide
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with  Unknown user name  when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do
        // Reference: https://github.com/hatlord/snmpwn
        $string4 = /snmpwn\s.{0,1000}passwords\.txt/ nocase ascii wide
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with Unknown user name when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do.
        // Reference: https://github.com/hatlord/snmpwn
        $string5 = /snmpwn\.rb.{0,1000}\s\-\-hosts\s/ nocase ascii wide

    condition:
        any of them
}
