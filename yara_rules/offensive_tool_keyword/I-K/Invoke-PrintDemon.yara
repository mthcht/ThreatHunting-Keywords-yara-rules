rule Invoke_PrintDemon
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PrintDemon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PrintDemon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is an PowerShell Empire launcher PoC using PrintDemon and Faxhell. The module has the Faxhell DLL already embedded which leverages CVE-2020-1048 for privilege escalation. The vulnerability allows an unprivileged user to gain system-level privileges and is based on @ionescu007 PoC.
        // Reference: https://github.com/BC-SECURITY/Invoke-PrintDemon
        $string1 = /Invoke\-PrintDemon/ nocase ascii wide

    condition:
        any of them
}
