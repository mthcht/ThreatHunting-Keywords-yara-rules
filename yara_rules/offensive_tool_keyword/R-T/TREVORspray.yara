rule TREVORspray
{
    meta:
        description = "Detection patterns for the tool 'TREVORspray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TREVORspray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string1 = /\/TREVORspray\.git/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string2 = /\/trevorspray\.log/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string3 = /\/tried_logins\.txt/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string4 = /blacklanternsecurity\/trevorproxy/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string5 = /blacklanternsecurity\/TREVORspray/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string6 = /import\sBaseSprayModule/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string7 = /spray.{0,1000}\s\-\-recon\s.{0,1000}\..{0,1000}\s\-u\s.{0,1000}\.txt\s\-\-threads\s10/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string8 = /TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string9 = /trevorproxy\sssh/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string10 = /trevorproxy\ssubnet/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string11 = /trevorspray\s\-/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string12 = /trevorspray\.cli/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string13 = /trevorspray\.enumerators/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string14 = /trevorspray\.looters/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string15 = /trevorspray\.py/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string16 = /trevorspray\.sprayers/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string17 = /trevorspray\/existent_users\.txt/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string18 = /trevorspray\/valid_logins\.txt/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string19 = /TREVORspray\-dev/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string20 = /TREVORspray\-master/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string21 = /TREVORspray\-trevorspray/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string22 = /Your\sMoms\sSmart\sVibrator/ nocase ascii wide

    condition:
        any of them
}
