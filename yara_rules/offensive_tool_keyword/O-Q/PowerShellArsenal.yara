rule PowerShellArsenal
{
    meta:
        description = "Detection patterns for the tool 'PowerShellArsenal' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShellArsenal"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShellArsenal is a PowerShell module used to aid a reverse engineer. The module can be used to disassemble managed and unmanaged code. perform .NET malware analysis. analyze/scrape memory. parse file formats and memory structures. obtain internal system information. etc.
        // Reference: https://github.com/mattifestation/PowerShellArsenal
        $string1 = /PowerShellArsenal/ nocase ascii wide

    condition:
        any of them
}
