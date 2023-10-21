rule PKINITtools
{
    meta:
        description = "Detection patterns for the tool 'PKINITtools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PKINITtools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string1 = /\/httpattack\.py/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string2 = /\/ntlmrelayx\// nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string3 = /\/PKINITtools/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string4 = /\=Administrator\.ccache/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string5 = /export\sKRB5CCNAME\=.*\.ccache/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string6 = /getnthash\.py/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string7 = /gets4uticket\.py/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string8 = /gettgtpkinit\.py/ nocase ascii wide

    condition:
        any of them
}