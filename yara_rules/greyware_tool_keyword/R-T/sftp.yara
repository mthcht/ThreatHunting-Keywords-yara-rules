rule sftp
{
    meta:
        description = "Detection patterns for the tool 'sftp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sftp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string1 = /\/sftp\s.{0,1000}\@.{0,1000}\:.{0,1000}\s/ nocase ascii wide
        // Description: sftp transfers of sensitive files
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string2 = /\/sftp\s.{0,1000}get.{0,1000}\.wallet/ nocase ascii wide
        // Description: sftp  archive transfers
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string3 = /\/sftp\s.{0,1000}put.{0,1000}\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}
