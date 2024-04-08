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
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string3 = /654c673c177a2a06c2b240ee07f81dc9096b1626f82855dc67722a5e10bbf6a1/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string4 = /654c673c177a2a06c2b240ee07f81dc9096b1626f82855dc67722a5e10bbf6a1/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string5 = /7de9505c6a9be2ff8b308140d28e9318a6045529f70a48bd7ce4115d263988cb/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string6 = /91ae5ce613fa82b7764401fb12fb8977a0b3c78325faa16f30abeb3dfbe9c71a/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string7 = /b83ee6d62e5e159fa0a16fcad953862a1d567abc5c60aa35dc02aac7efc87870/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string8 = /b83ee6d62e5e159fa0a16fcad953862a1d567abc5c60aa35dc02aac7efc87870/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string9 = /d2d99c2dcb17923e9ce1d91e16491527edcdd945aa68e54d83bc6fc927274b05/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string10 = /d2d99c2dcb17923e9ce1d91e16491527edcdd945aa68e54d83bc6fc927274b05/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string11 = /d44d0425769fa2e0b6875e5ca25d45b251bbe98870c6b9bef34f7cea9f84c9c3/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string12 = /d44d0425769fa2e0b6875e5ca25d45b251bbe98870c6b9bef34f7cea9f84c9c3/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string13 = /ece869c6e359a650da3a82c8d26239bde4293a591c0d634815595129654665ae/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string14 = /ece869c6e359a650da3a82c8d26239bde4293a591c0d634815595129654665ae/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string15 = /eval\s\$zrKcKQ/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string16 = /ffcd092a7d9ec7d79a115e3e98f4509bee3e3977e401967140e2e5de061f8a0b/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string17 = /G1Q\+4a0TgAHnlq2B8BKLZUP6wDHsjX6F5nVtUTU3dBQ/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: Elastic Security - link: https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Trojan_XZBackdoor.yar
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string18 = /yolAbejyiejuvnup\=Evjtgvsh5okmkAvj/ nocase ascii wide

    condition:
        any of them
}
