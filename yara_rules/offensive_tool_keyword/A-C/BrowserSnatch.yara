rule BrowserSnatch
{
    meta:
        description = "Detection patterns for the tool 'BrowserSnatch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BrowserSnatch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string1 = /\/BrowserSnatch\.git/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string2 = "/BrowserSnatch/releases/download" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string3 = "/BrowserSnatch-master" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string4 = /\\BrowserSnatch\.sln/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string5 = /\\BrowserSnatch\-master/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string6 = /\\ChromiumDecryptor\.cpp/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string7 = "08cebde6781422f271581951ff6db23b9eedd4a0be0949551c0da85c6de8cb72" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string8 = "0f898913633b4dad45a631e63466f6b76e591f896118bab6e718ab3c8587911f" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string9 = "3246bb6e6b258b85286ae566dbde16e6e61c35d21be06a0d03b1aad376efb411" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string10 = "3f8db721f5791fcaaef7d22b50a1cd6a87be8f07262c145ad66a18f832d75839" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string11 = "493e415ef774fe3a7c3ba17a524f02d72bd36b1a49d8e9e0734eecf1d5834155" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string12 = "569d0ac16a89509e1de01deab2fefe2731a48bec2ab7794d9ac0628a6baf2481" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string13 = "7dbc46ea673ab508a7b9121b0a49d29470a8fc01669105173fd2a52f88dd946a" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string14 = "7de6e20c24d452409937f4869770848445952afa1ff26288dfb558d8edc64def" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string15 = "87440f0b-dacf-4695-a483-031fdc0b0194" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string16 = "a3fbc9a01ac82d10f92da72625f1a092817c5fad7a9b60917b811fab1ff8c97f" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string17 = "BrowserSnatch -" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string18 = "BrowserSnatch executed with " nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string19 = /BrowserSnatch\sv1\.0\s\-\sA\sversatile\sbrowser\sdata\sextraction\stool/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string20 = /BrowserSnatch\.exe/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string21 = /BrowserSnatch64\.exe/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string22 = /BrowserSnatch\-master\.zip/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string23 = "Chromium Bookmarks Snatch Failed" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string24 = "Chromium Cookie Snatch Failed" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string25 = "Chromium History Snatch Failed" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string26 = "Chromium Password Snatch Failed" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string27 = "dc12cf2c161aea6ad015a11593b74603e25a4c7754b96b3d3b4062bd0e5d5a09" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string28 = /dns\.msfncsi\.com/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string29 = "e7711f13b26f4b8f260587592d92f5d04e4aec5124896a35f082b69785e51d26" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string30 = "f58cbacfd41c4b0d5411a48f8142489dbde75c79211f37cb3c11a5063ebb6c2f" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string31 = "Gecko Bookmarks Snatch Failed" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string32 = "Gecko Cookie Snatch Failed" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string33 = "Gecko History Snatch Failed" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string34 = "Gecko Password Snatch Failed" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string35 = /https\:\/\/0x00sec\.org\/t\/malware\-development\-1\-password\-stealers\-chrome\/33571/ nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string36 = "shaddy43/BrowserSnatch" nocase ascii wide
        // Description: steals important data from all chromium and gecko browsers installed in the system and gather the data in a stealer db to be exfiltrated out. A powerful Browser Stealer
        // Reference: https://github.com/shaddy43/BrowserSnatch
        $string37 = "Snatching passwords & cookies" nocase ascii wide

    condition:
        any of them
}
