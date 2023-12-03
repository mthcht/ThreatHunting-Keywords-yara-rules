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
        $string1 = /.{0,1000}\/httpattack\.py.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string2 = /.{0,1000}\/ntlmrelayx\/.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string3 = /.{0,1000}\/PKINITtools.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string4 = /.{0,1000}\=Administrator\.ccache.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string5 = /.{0,1000}dirkjanm\/PKINITtools.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string6 = /.{0,1000}export\sKRB5CCNAME\=.{0,1000}\.ccache.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string7 = /.{0,1000}getnthash\.py.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string8 = /.{0,1000}gets4uticket\.py.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string9 = /.{0,1000}gettgtpkinit\.py.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string10 = /.{0,1000}impacket\sminikerberos.{0,1000}/ nocase ascii wide
        // Description: Tools for Kerberos PKINIT and relaying to AD CS
        // Reference: https://github.com/dirkjanm/PKINITtools
        $string11 = /.{0,1000}PKINITtools\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
