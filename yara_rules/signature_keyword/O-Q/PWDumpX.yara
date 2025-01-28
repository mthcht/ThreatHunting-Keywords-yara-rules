rule PWDumpX
{
    meta:
        description = "Detection patterns for the tool 'PWDumpX' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWDumpX"
        rule_category = "signature_keyword"

    strings:
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string1 = /HKTL_PWDUMP\./ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string2 = /PSWTool\.Win32\.PWDump/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string3 = "PWCrack-PWDump" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string4 = /PWDumpX\s\(PUA\)/ nocase ascii wide

    condition:
        any of them
}
