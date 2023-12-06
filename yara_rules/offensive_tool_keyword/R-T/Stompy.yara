rule Stompy
{
    meta:
        description = "Detection patterns for the tool 'Stompy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stompy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string1 = /\sStompy\.ps1/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string2 = /\sStomPY\.py\s/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string3 = /\.\/GoStompy\s/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string4 = /\.exe.{0,1000}\s\-path\s.{0,1000}\s\-newTimestamp\s.{0,1000}\s\-username\s.{0,1000}\s\-password\s/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string5 = /\/GoStompy\.go/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string6 = /\/Stompy\.git/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string7 = /\/Stompy\.ps1/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string8 = /\/StomPY\.py/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string9 = /\\GoStompy\.go/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string10 = /\\Stompy\.ps1/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string11 = /\\StomPY\.py/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string12 = /\\Stompy\-main\\/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string13 = /784F8029\-4D72\-4363\-9638\-5A8D11545494/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string14 = /build\sGoStompy\.go/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string15 = /Invoke\-Stompy/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string16 = /StompySharps\.csproj/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string17 = /StompySharps\.exe/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string18 = /StompySharps\.sln/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string19 = /ZephrFish\/Stompy/ nocase ascii wide

    condition:
        any of them
}
