rule RITM
{
    meta:
        description = "Detection patterns for the tool 'RITM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RITM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string1 = /\simport\sSpoofer\,\sSniffer\,\sRoaster/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string2 = /\sroaster\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string3 = /\ssniffer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string4 = /\sspoofer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string5 = /\/RITM\.git/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string6 = /\/roaster\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string7 = /\/sniffer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string8 = /\/spoofer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string9 = /\\roaster\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string10 = /\\sniffer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string11 = /\\spoofer\.py/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string12 = /387e21adbabeddf80db5d2868f93d6bdba8443dc26fdb964ec6e279f3d02310c/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string13 = /ad393f135cc101f7897812ad3183775a89853e89cab5f31ae89eef3240ca9c4f/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string14 = /f1525ffa97500a9aa64138541d1e91f403e494d8a6eef7bcb1f1de7e8261755e/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string15 = /from\sritm\.lib\simport\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string16 = /from\sritm\.logger\simport\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string17 = /I\sneed\sroooot\.\sUnable\sto\sopen\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string18 = /impacket\.krb5\./ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string19 = /poetry\srun\sritm\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string20 = /\'Roasted\sSPN\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string21 = /Sniffed\sAS\-REQ\sfrom\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string22 = /Sniffer\swaiting\sfor\sAS\-REQ/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string23 = /The\sAS\-REQ\sis\svalid\!\sAttempting\sto\sroast\s/ nocase ascii wide
        // Description: python Man in the middle 
        // Reference: https://github.com/Tw1sm/RITM
        $string24 = /Tw1sm\/RITM/ nocase ascii wide

    condition:
        any of them
}
