rule Godzilla
{
    meta:
        description = "Detection patterns for the tool 'Godzilla' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Godzilla"
        rule_category = "signature_keyword"

    strings:
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string1 = /Backdoor\:ASP\/Chopper\.ZC\!dha/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string2 = /TrojanDownloader\:Java\/GodzillaWebShell/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string3 = /TrojanDownloader\:Java\/GodzillaWebShell\.C/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string4 = /VirTool\:MSIL\/DarkStealer\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}
