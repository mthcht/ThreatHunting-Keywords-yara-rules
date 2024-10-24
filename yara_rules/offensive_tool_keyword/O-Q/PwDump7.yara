rule PwDump7
{
    meta:
        description = "Detection patterns for the tool 'PwDump7' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PwDump7"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string1 = /\/pwdump7\.zip/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string2 = /\\pwdump7/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string3 = /\\pwdump7\.zip/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string4 = /b20f667c2539954744ddcb7f1d673c2a6dc0c4a934df45a3cca15a203a661c88/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string5 = /ee29e80a2e8c469655fe215eac14c2fbb201116e40fd056dcd1f602e1959263b/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string6 = /Pwdump\sv7\.1\s\-\sraw\spassword\sextractor/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://www.openwall.com/passwords/windows-pwdump
        $string7 = /PwDump7\.exe/ nocase ascii wide

    condition:
        any of them
}
