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
        $string1 = /.{0,1000}\.exe.{0,1000}\\Terminator\.sys.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string2 = /.{0,1000}\/SharpTerminator\/.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string3 = /.{0,1000}\/terminate\/Terminator\.sys.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string4 = /.{0,1000}\\SharpTerminator\.csproj.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string5 = /.{0,1000}http.{0,1000}:\/\/.{0,1000}\/Terminator\.sys/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string6 = /.{0,1000}mertdas\/SharpTerminator.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string7 = /.{0,1000}sc\screate\sTerminator\s.{0,1000}\.sys.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string8 = /.{0,1000}SharpTerminator\.exe.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string9 = /.{0,1000}SharpTerminator\.git.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string10 = /.{0,1000}SharpTerminator\.sln.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR Processes using kernel driver
        // Reference: https://github.com/mertdas/SharpTerminator
        $string11 = /.{0,1000}SharpTerminator\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
