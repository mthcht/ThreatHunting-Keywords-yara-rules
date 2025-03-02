rule SessionExec
{
    meta:
        description = "Detection patterns for the tool 'SessionExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Execute commands in other Sessions
        // Reference: https://github.com/Leo4j/SessionExec
        $string1 = /\/SessionExec\.exe/ nocase ascii wide
        // Description: Execute commands in other Sessions
        // Reference: https://github.com/Leo4j/SessionExec
        $string2 = /\\SessionExec\.exe/ nocase ascii wide
        // Description: Execute commands in other Sessions
        // Reference: https://github.com/Leo4j/SessionExec
        $string3 = "9065655de782c08c41aa0fe11503e92e455fdf4b1a590101221aeb73f8db98e9" nocase ascii wide
        // Description: Execute commands in other Sessions
        // Reference: https://github.com/Leo4j/SessionExec
        $string4 = "function Invoke-SessionExec" nocase ascii wide
        // Description: Execute commands in other Sessions
        // Reference: https://github.com/Leo4j/SessionExec
        $string5 = "Invoke-SessionExec " nocase ascii wide
        // Description: Execute commands in other Sessions
        // Reference: https://github.com/Leo4j/SessionExec
        $string6 = /Invoke\-SessionExec\.ps1/ nocase ascii wide

    condition:
        any of them
}
