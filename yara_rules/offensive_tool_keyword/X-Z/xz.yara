rule xz
{
    meta:
        description = "Detection patterns for the tool 'xz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string1 = /\/bad\-3\-corrupt_lzma2\.xz\s\|\str\s/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string2 = /\/tests\/files\/good\-large_compressed\.lzma\|eval\s\$i\|tail\s\-c\s\+31265\|/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string3 = /eval\s\$zrKcKQ/ nocase ascii wide

    condition:
        any of them
}
