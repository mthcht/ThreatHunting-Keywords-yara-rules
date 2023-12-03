rule ExtractBitlockerKeys
{
    meta:
        description = "Detection patterns for the tool 'ExtractBitlockerKeys' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtractBitlockerKeys"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string1 = /.{0,1000}\.ps1\s\-dcip\s.{0,1000}\s\-Username\s.{0,1000}\s\-Password.{0,1000}\s\-ExportToCSV\s.{0,1000}\.csv\s\-ExportToJSON\s.{0,1000}\.json.{0,1000}/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string2 = /.{0,1000}\/ExtractBitlockerKeys\.git.{0,1000}/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string3 = /.{0,1000}ExtractBitLockerKeys.{0,1000}\@podalirius_.{0,1000}/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string4 = /.{0,1000}ExtractBitlockerKeys\.ps1.{0,1000}/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string5 = /.{0,1000}ExtractBitlockerKeys\.py.{0,1000}/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string6 = /.{0,1000}ExtractBitlockerKeys\-main.{0,1000}/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string7 = /.{0,1000}p0dalirius\/ExtractBitlockerKeys.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
