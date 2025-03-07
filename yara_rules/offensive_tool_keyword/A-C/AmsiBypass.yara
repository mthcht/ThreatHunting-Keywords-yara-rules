rule AmsiBypass
{
    meta:
        description = "Detection patterns for the tool 'AmsiBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmsiBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string1 = /\/AmsiBypass\./ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string2 = /\/Amsi\-Bypass\-Powershell\.git/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string3 = "/opt/Projects/AmsiBypass/"
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string4 = /\\AmsiBypass\./ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string5 = "132ab5d9aa388ae3a6575a01fadeb7fa7f77aac1150fc54bc1d20ae32b58ddc5" nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string6 = "Invoke-PsUACme -Method " nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string7 = "Modified-Amsi-ScanBuffer-Patch" nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string8 = "Nishang-all-in-one" nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string9 = "Patching-AMSI-AmsiScanBuffer-by-rasta-mouse" nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string10 = "S3cur3Th1sSh1t/Amsi-Bypass-Powershell" nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string11 = /\'System\.Ma\'\+\'nag\'\+\'eme\'\+\'nt\.Autom\'\+\'ation\.A\'\+\'ms\'\+\'iU\'\+\'ti\'\+\'ls\'/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string12 = "Tztufn/Nbobhfnfou/Bvupnbujpo/BntjVujmt" nocase ascii wide

    condition:
        any of them
}
