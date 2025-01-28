rule DecryptTeamViewer
{
    meta:
        description = "Detection patterns for the tool 'DecryptTeamViewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DecryptTeamViewer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string1 = /\/DecryptTeamViewer\.exe/ nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string2 = /\/DecryptTeamViewer\.git/ nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string3 = /\\DecryptTeamViewer\.exe/ nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string4 = /\\DecryptTeamViewer\.sln/ nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string5 = /\\DecryptTeamViewer\-master/ nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string6 = "4aa99dcaf5030b1c4c7c57edd0fea22ab6db79caff79a547cc07572077631646" nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string7 = "7ec9b36feeace5d4903be2adb2e1454af948a393c311b5513bfad0e9995b87e7" nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string8 = "D6AAED62-BBFC-4F2A-A2A4-35EC5B2A4E07" nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string9 = "DecryptTeamViewer: Pillaging registry for TeamViewer information" nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string10 = /DecryptTeamViewer\-master\.zip/ nocase ascii wide
        // Description: Enumerate and decrypt TeamViewer credentials from Windows registry
        // Reference: https://github.com/V1V1/DecryptTeamViewer
        $string11 = "V1V1/DecryptTeamViewer" nocase ascii wide

    condition:
        any of them
}
