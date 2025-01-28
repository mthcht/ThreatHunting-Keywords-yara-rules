rule crackmd5_ru
{
    meta:
        description = "Detection patterns for the tool 'crackmd5.ru' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crackmd5.ru"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: site to crack md5 hashes used by Dispossessor ransomware groups and many others
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = /www\.crackmd5\.ru/ nocase ascii wide

    condition:
        any of them
}
