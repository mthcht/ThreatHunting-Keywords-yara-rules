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
        $string1 = /.{0,1000}\sStompy\.ps1.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string2 = /.{0,1000}\sStomPY\.py\s.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string3 = /.{0,1000}\.\/GoStompy\s.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string4 = /.{0,1000}\.exe.{0,1000}\s\-path\s.{0,1000}\s\-newTimestamp\s.{0,1000}\s\-username\s.{0,1000}\s\-password\s.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string5 = /.{0,1000}\/GoStompy\.go.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string6 = /.{0,1000}\/Stompy\.git.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string7 = /.{0,1000}\/Stompy\.ps1.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string8 = /.{0,1000}\/StomPY\.py.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string9 = /.{0,1000}\\GoStompy\.go.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string10 = /.{0,1000}\\Stompy\.ps1.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string11 = /.{0,1000}\\StomPY\.py.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string12 = /.{0,1000}\\Stompy\-main\\.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string13 = /.{0,1000}784F8029\-4D72\-4363\-9638\-5A8D11545494.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string14 = /.{0,1000}build\sGoStompy\.go.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string15 = /.{0,1000}Invoke\-Stompy.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string16 = /.{0,1000}StompySharps\.csproj.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string17 = /.{0,1000}StompySharps\.exe.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string18 = /.{0,1000}StompySharps\.sln.{0,1000}/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string19 = /.{0,1000}ZephrFish\/Stompy.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
