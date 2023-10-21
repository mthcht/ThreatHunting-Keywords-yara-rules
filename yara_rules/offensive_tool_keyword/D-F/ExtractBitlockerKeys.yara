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
        $string1 = /\.ps1\s\-dcip\s.*\s\-Username\s.*\s\-Password.*\s\-ExportToCSV\s.*\.csv\s\-ExportToJSON\s.*\.json/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string2 = /\/ExtractBitlockerKeys\.git/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string3 = /ExtractBitLockerKeys.*\@podalirius_/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string4 = /ExtractBitlockerKeys\.ps1/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string5 = /ExtractBitlockerKeys\.py/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string6 = /ExtractBitlockerKeys\-main/ nocase ascii wide
        // Description: A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.
        // Reference: https://github.com/p0dalirius/ExtractBitlockerKeys
        $string7 = /p0dalirius\/ExtractBitlockerKeys/ nocase ascii wide

    condition:
        any of them
}