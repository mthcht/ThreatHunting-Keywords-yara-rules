rule Xworm
{
    meta:
        description = "Detection patterns for the tool 'Xworm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xworm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string1 = /\/Command\sReciever\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string2 = /\/Command\%20Reciever\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string3 = /\/DeleteWD\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string4 = /\/DisableWD\.dll\,/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string5 = /\/HVNC\-Server\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string6 = /\/Keylogger\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string7 = /\/Ngrok\-Disk\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string8 = /\/Ngrok\-Install\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string9 = /\/PHVNC\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string10 = /\/Plugins\/HRDP\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string11 = /\/Plugins\/HVNC\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string12 = /\/Plugins\/PreventSleep\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string13 = /\/Ransomware\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string14 = /\/Ransomware\.pdb/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string15 = /\/Tools\/ResHacker\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string16 = /\/UACBypass\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string17 = /\/WDExclusion\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string18 = /\/WifiKeys\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string19 = /\/Worm\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string20 = /\/XHVNC\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string21 = /\/XWorm\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string22 = /\/XWorm\.zip/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string23 = /\/XWorm\-RAT\-V/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string24 = /\\Command\sReciever\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string25 = /\\DeleteWD\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string26 = /\\DisableWD\.dll\,/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string27 = /\\HVNC\-Server\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string28 = /\\Keylogger\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string29 = /\\KillWindows\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string30 = /\\KillWindows\.pdb/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string31 = /\\Ngrok\-Disk\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string32 = /\\Ngrok\-Install\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string33 = /\\PHVNC\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string34 = /\\PHVNC\.pdb/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string35 = /\\Plugins\\HRDP\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string36 = /\\Plugins\\HVNC\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string37 = /\\Plugins\\PreventSleep\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string38 = /\\Ransomware\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string39 = /\\Ransomware\.pdb/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string40 = /\\SOFTWARE\\Xworm/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string41 = /\\Tools\\ResHacker\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string42 = /\\UACBypass\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string43 = /\\WDExclusion\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string44 = /\\WDExclusion\.pdb/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string45 = /\\WifiKeys\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string46 = /\\WifiKeys\.pdb/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string47 = /\\Worm\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string48 = /\\XHVNC\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string49 = /\\XWorm\sRAT\sV/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string50 = /\\XWorm\.exe/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string51 = /\\XWorm\.zip/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string52 = /\\XWorm\-RAT\-/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string53 = /23ed5325043d0b9e7a9115792b12817cec836ba09e5af2aab3408606da729681/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string54 = /2bd33a784af634af7590ad9dc43d574005dd95b2b2e20640b97cff0474af91c6/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string55 = /5b32dad4ad2b350157eda3061dc821645e7cd291970509ab32e9023b8c945951/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string56 = /67d9b4b35c02a19ab364ad19e1972645eb98e24dcd6f1715d2a26229deb2ccf5/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string57 = /815dfb13e0c4d5040ffb1dde7350cc77f227b2945b01c61bf54f85eefdd182cf/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string58 = /995e755827bf8c1908e64d40a7851e05706b89e41dee63037e5c4be0b61f113e/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string59 = /Cmstp\-Bypass\.dll/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string60 = /Cmstp\-Bypass\.pdb/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string61 = /d384ec908583b271588a27748850e4cadf9d8b55a4afdfa54170738da54fc4ef/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string62 = /e92707537fe99713752f3d3f479fa68a0c8dd80439c13a2bb4ebb36a952b63fd/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string63 = /ea912ca7c74d76924cdf1e634164d723a6d7a48212ab03c0f343a0132754a41b/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string64 = /ea9258e9975b8925a739066221d996aef19b4ef4f4c91524f82e39d403f25579/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string65 = /HVNC\.Properties/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string66 = /If\sXWorm\sDoes\sNot\swork\s\-\sRun\sThis\sScript\sAs\sAdministrator\!/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string67 = /Keylogger\.My/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string68 = /UACBypass\.My/ nocase ascii wide
        // Description: Malware with wide range of capabilities ranging from RAT to ransomware
        // Reference: https://github.com/guessthatname99/XWorm-RAT-V2.1
        $string69 = /XWorm_RAT_V2\._1\.data\./ nocase ascii wide

    condition:
        any of them
}
