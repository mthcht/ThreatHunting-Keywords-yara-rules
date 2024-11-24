rule IHxExec
{
    meta:
        description = "Detection patterns for the tool 'IHxExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IHxExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string1 = /\/IHxExec\.exe/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string2 = /\/IHxExec\.git/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string3 = /\/IHxExec\-main\.zip/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string4 = /\\IHxExec\.cpp/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string5 = /\\IHxExec\.exe/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string6 = /\\IHxExec\.vcxproj/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string7 = /\\IHxExec\-main/ nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string8 = "165a010438ef6f3b9d8dfbb47e486740e5d8235e77d28efb7b7c1b93654f71b4" nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string9 = "c0ac59bed2e0208db150069c4d943a73036d03271754075029bc2e41f24bb303" nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string10 = "CICADA8-Research/IHxExec" nocase ascii wide
        // Description: Process injection technique
        // Reference: https://github.com/CICADA8-Research/IHxExec
        $string11 = "d5092358-f3ab-4712-9c7f-d9ec4390193c" nocase ascii wide

    condition:
        any of them
}
