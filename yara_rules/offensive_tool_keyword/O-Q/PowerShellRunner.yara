rule PowerShellRunner
{
    meta:
        description = "Detection patterns for the tool 'PowerShellRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShellRunner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell runner for executing malicious payloads in order to bypass Windows Defender
        // Reference: https://github.com/dievus/PowerShellRunner
        $string1 = /\/PowerShellRunner\.git/ nocase ascii wide
        // Description: PowerShell runner for executing malicious payloads in order to bypass Windows Defender
        // Reference: https://github.com/dievus/PowerShellRunner
        $string2 = "3f3dfb593302ddb3b356daea1e47c3ffdeb0f304f5eef51b7aeecd1b2f15538f" nocase ascii wide
        // Description: PowerShell runner for executing malicious payloads in order to bypass Windows Defender
        // Reference: https://github.com/dievus/PowerShellRunner
        $string3 = "8903483f5b5e84041ec7a90bab38a4b430c28925717cb09c3199f46952046aa7" nocase ascii wide
        // Description: PowerShell runner for executing malicious payloads in order to bypass Windows Defender
        // Reference: https://github.com/dievus/PowerShellRunner
        $string4 = "dievus/PowerShellRunner" nocase ascii wide
        // Description: PowerShell runner for executing malicious payloads in order to bypass Windows Defender
        // Reference: https://github.com/dievus/PowerShellRunner
        $string5 = /PowerShellRunner.{0,1000}runner\.ps1/ nocase ascii wide

    condition:
        any of them
}
