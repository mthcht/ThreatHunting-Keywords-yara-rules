rule Invisi_Shell
{
    meta:
        description = "Detection patterns for the tool 'Invisi-Shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invisi-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging. Module logging. Transcription. AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.
        // Reference: https://github.com/OmerYa/Invisi-Shell
        $string1 = /Invisi\-Shell/ nocase ascii wide

    condition:
        any of them
}
