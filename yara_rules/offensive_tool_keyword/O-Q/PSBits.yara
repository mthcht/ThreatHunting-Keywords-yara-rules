rule PSBits
{
    meta:
        description = "Detection patterns for the tool 'PSBits' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSBits"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple tool enabling all privileges in the parent process (usually cmd.exe) token. Useful if you have SeBackup or SeRestore and need a cmd.exe ignoring all ACLs
        // Reference: https://github.com/gtworek/PSBits/tree/master/EnableAllParentPrivileges
        $string1 = /EnableAllParentPrivileges\.c/ nocase ascii wide
        // Description: Simple tool enabling all privileges in the parent process (usually cmd.exe) token. Useful if you have SeBackup or SeRestore and need a cmd.exe ignoring all ACLs
        // Reference: https://github.com/gtworek/PSBits/tree/master/EnableAllParentPrivileges
        $string2 = /EnableAllParentPrivileges\.exe/ nocase ascii wide

    condition:
        any of them
}
