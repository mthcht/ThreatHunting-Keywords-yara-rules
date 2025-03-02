rule DitExplorer
{
    meta:
        description = "Detection patterns for the tool 'DitExplorer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DitExplorer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string1 = /\/DitExplorer\.git/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string2 = "/DitExplorer/releases/download/" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string3 = "/DitExplorer/releases/tag/v" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string4 = "/DitExplorer/tarball/" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string5 = "/DitExplorer/zipball/" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string6 = /\\DitExplorer\.sln/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string7 = ">DIT Explorer<" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string8 = "29021B28-61F9-492D-BB51-7CA8889087E5" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string9 = "8714f9c15c56b5a6aebb5e90fe59a2f952df8f0759d776e851a1064f159e89a0" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string10 = "933f98396260d2400250b8bd4897ab13bf4399fa276fa1e20391a446da68b4cc" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string11 = "A71FCCEB-C1C5-4ADB-A949-462B653C2937" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string12 = "AD240C26-717F-4937-A4CD-5827BDC315E6" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string13 = "AEC0EBBA-3BE4-4B5C-8F5C-0BB8DDDA7148" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string14 = "cc9d7b88c9fe25358764727439bc55d5df36dc828b2b620b05c9b6129109588a" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string15 = "CDC4F57A-A3F7-459B-87BF-6219DADF6284" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string16 = "d044393f7a9e9536cc03cec12137074d41dd338c0182bbd8a4ca165f79f5a3d9" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string17 = "D1D4BB1C-798D-47B0-8525-061D40CB9E44" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string18 = "DIT Explorer Credential Extractor" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string19 = /DitExplorer\.Core/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string20 = /DitExplorer\.CredentialExtraction/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string21 = /DitExplorer\.EseInterop/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string22 = /DitExplorer\.Ntds/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string23 = /DitExplorer\.UI\./ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string24 = /DitExplorer\.UI\.WpfApp\.dll/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string25 = /DitExplorer\.UI\.WpfApp\.exe/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string26 = /DitExplorer\-v1\.0\-win64\-release\.zip/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string27 = /DitExplorer\-v1\.0\-win64\-release\-standalone\.zip/ nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string28 = "E2596512-8A36-4D48-8AA1-9791E48A16CC" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string29 = "e8467998e22a50d952a786c2ce337493cdd4d32a7e035a7af58bdc3c9b3f17ed" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string30 = "E8CA6917-CB06-4128-96CD-59676731B24A" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string31 = "f55b17e5f63a4f87b16061fc2d44c366bd5868c30104ef273e783c087d2ef3cb" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string32 = "trustedsec/DitExplorer" nocase ascii wide
        // Description: Tool for viewing NTDS.dit
        // Reference: https://github.com/trustedsec/DitExplorer
        $string33 = /you\'ll\sneed\sthe\ssystem\skey\sof\sthe\sDC\sthat\syou\spulled\sthe\sNTDS\.dit\sfile/ nocase ascii wide

    condition:
        any of them
}
