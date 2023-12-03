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
        $string1 = /.{0,1000}\/TREVORspray\.git.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string2 = /.{0,1000}\/trevorspray\.log.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string3 = /.{0,1000}\/tried_logins\.txt.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string4 = /.{0,1000}blacklanternsecurity\/trevorproxy.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string5 = /.{0,1000}blacklanternsecurity\/TREVORspray.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string6 = /.{0,1000}import\sBaseSprayModule.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string7 = /.{0,1000}spray.{0,1000}\s\-\-recon\s.{0,1000}\..{0,1000}\s\-u\s.{0,1000}\.txt\s\-\-threads\s10.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string8 = /.{0,1000}TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string9 = /.{0,1000}trevorproxy\sssh.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string10 = /.{0,1000}trevorproxy\ssubnet.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string11 = /.{0,1000}trevorspray\s\-.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string12 = /.{0,1000}trevorspray\.cli.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string13 = /.{0,1000}trevorspray\.enumerators.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string14 = /.{0,1000}trevorspray\.looters.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string15 = /.{0,1000}trevorspray\.py.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string16 = /.{0,1000}trevorspray\.sprayers.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string17 = /.{0,1000}trevorspray\/existent_users\.txt.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string18 = /.{0,1000}trevorspray\/valid_logins\.txt.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string19 = /.{0,1000}TREVORspray\-dev.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string20 = /.{0,1000}TREVORspray\-master.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string21 = /.{0,1000}TREVORspray\-trevorspray.{0,1000}/ nocase ascii wide
        // Description: TREVORspray is a modular password sprayer with threading - clever proxying - loot modules and more
        // Reference: https://github.com/blacklanternsecurity/TREVORspray
        $string22 = /.{0,1000}Your\sMoms\sSmart\sVibrator.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
