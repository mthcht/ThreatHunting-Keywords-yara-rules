rule LDAPPER
{
    meta:
        description = "Detection patterns for the tool 'LDAPPER' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LDAPPER"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LDAP Querying without the Suck
        // Reference: https://github.com/shellster/LDAPPER
        $string1 = /\sldapper\.py/ nocase ascii wide
        // Description: LDAP Querying without the Suck
        // Reference: https://github.com/shellster/LDAPPER
        $string2 = /\/LDAPPER\.git/ nocase ascii wide
        // Description: LDAP Querying without the Suck
        // Reference: https://github.com/shellster/LDAPPER
        $string3 = /\/ldapper\.py/ nocase ascii wide
        // Description: LDAP Querying without the Suck
        // Reference: https://github.com/shellster/LDAPPER
        $string4 = /\/LDAPPER\-master/ nocase ascii wide
        // Description: LDAP Querying without the Suck
        // Reference: https://github.com/shellster/LDAPPER
        $string5 = /\\ldapper\.py/ nocase ascii wide
        // Description: LDAP Querying without the Suck
        // Reference: https://github.com/shellster/LDAPPER
        $string6 = /\\LDAPPER\-master/ nocase ascii wide
        // Description: LDAP Querying without the Suck
        // Reference: https://github.com/shellster/LDAPPER
        $string7 = /AD\sLDAP\sCommand\sLine\sSearching\sthat\sdoesn\'t\ssuck\./ nocase ascii wide
        // Description: LDAP Querying without the Suck
        // Reference: https://github.com/shellster/LDAPPER
        $string8 = /shellster\/LDAPPER/ nocase ascii wide

    condition:
        any of them
}
