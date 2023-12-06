rule DKMC
{
    meta:
        description = "Detection patterns for the tool 'DKMC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DKMC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string1 = /\/DKMC\.git/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string2 = /\/dkmc\.py/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string3 = /\/sc\-loader\.exe/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string4 = /\\dkmc\.py/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string5 = /\\sc\-loader\.exe/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string6 = /DKMC\-master\.zip/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string7 = /downloadshellcodebin\.c/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string8 = /downloadshellcodebin\.exe/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string9 = /exec\-sc\-rand\.ps1/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string10 = /JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBDAEYAVABUAEwAVgBrAEMALwB6AEUAMABPAFQAWQB/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string11 = /MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9ZoKnCHwsOdxe/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string12 = /Module\sto\sgenerate\sshellcode\sout\sof\sraw\smetasploit\sshellcode\sfile/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string13 = /Mr\-Un1k0d3r\/DKMC/ nocase ascii wide
        // Description: Malicious payload evasion tool
        // Reference: https://github.com/Mr-Un1k0d3r/DKMC
        $string14 = /python\sdkmc\.py/ nocase ascii wide

    condition:
        any of them
}
