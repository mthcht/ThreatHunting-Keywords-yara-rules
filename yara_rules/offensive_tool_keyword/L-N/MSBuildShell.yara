rule MSBuildShell
{
    meta:
        description = "Detection patterns for the tool 'MSBuildShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSBuildShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a Powershell Host running within MSBuild.exe This code lets you Bypass Application Whitelisting and Powershell.exe restrictions and gives you a shell that almost looks and feels like a normal Powershell session (Get-Credential. PSSessions -> Works. Tab Completion -> Unfortunately not). It will also bypass the Antimalware Scan Interface (AMSI). which provides enhanced malware protection for Powershell scripts
        // Reference: https://github.com/Cn33liz/MSBuildShell
        $string1 = /MSBuildShell/ nocase ascii wide

    condition:
        any of them
}
