rule PwDump8
{
    meta:
        description = "Detection patterns for the tool 'PwDump8' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PwDump8"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
        $string1 = /\/pwdump8\./ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
        $string2 = /\\pwdump8/ nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
        $string3 = "eb046b68a014aded4f81bb952edadd283a0cd5a36fc416b89d391df3daaa6d9e" nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
        $string4 = "pwdump -f " nocase ascii wide
        // Description: pwdump7 works with its own filesytem driver (from rkdetector.com technology) so users with administrative privileges are able to dump directly from disk both SYSTEM and SAM registry hives. Once dumped - the SYSKEY key will be retrieved from the SYSTEM hive and then used to decrypt both LanMan and NTLM hashes and dump them in pwdump like format.
        // Reference: https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
        $string5 = /PwDump\sv8\.2\s\-\sdumps\swindows\spassword\shashes/ nocase ascii wide

    condition:
        any of them
}
