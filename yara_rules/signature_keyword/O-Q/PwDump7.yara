rule PwDump7
{
    meta:
        description = "Detection patterns for the tool 'PwDump7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PwDump7"
        rule_category = "signature_keyword"

    strings:
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string1 = /HackTool\.PasswordStealer/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string2 = /HackTool\.Win32\.PWDump/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string3 = /HackTool\.Win32\.PWDump/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string4 = "HackTool:Win32/PWDump" nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string5 = /PWCrack\-Pwdump\./ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string6 = /PWDump7\sRaw\sPassword\sExtractor\s\(PUA\)/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string7 = "Win32/PWDump" nocase ascii wide

    condition:
        any of them
}
