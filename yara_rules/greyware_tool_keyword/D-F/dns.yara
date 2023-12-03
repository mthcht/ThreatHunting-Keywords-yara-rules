rule dns
{
    meta:
        description = "Detection patterns for the tool 'dns' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml
        $string1 = /.{0,1000}\sdenied\sAXFR\sfrom\s.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml
        $string2 = /.{0,1000}\sdropping\ssource\sport\szero\spacket\sfrom\s.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml
        $string3 = /.{0,1000}\sexiting\s\(due\sto\sfatal\serror\).{0,1000}/ nocase ascii wide

    condition:
        any of them
}
