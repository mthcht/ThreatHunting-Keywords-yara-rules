rule SharpTerminator
{
    meta:
        description = "Detection patterns for the tool 'SharpTerminator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpTerminator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string1 = /\.exe.{0,1000}\\Terminator\.sys/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string2 = /\/SharpTerminator\// nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string3 = /\/terminate\/Terminator\.sys/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string4 = /\\SharpTerminator\.csproj/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string5 = /http.{0,1000}\:\/\/.{0,1000}\/Terminator\.sys/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string6 = /mertdas\/SharpTerminator/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string7 = /sc\screate\sTerminator\s.{0,1000}\.sys/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string8 = /SharpTerminator\.exe/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string9 = /SharpTerminator\.git/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string10 = /SharpTerminator\.sln/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string11 = /SharpTerminator\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
