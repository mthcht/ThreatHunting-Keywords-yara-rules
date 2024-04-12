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
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string3 = /0f5c81f14171b74fcc9777d302304d964e63ffc2d7b634ef023a7249d9b5d875/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string4 = /2398f4a8e53345325f44bdd9f0cc7401bd9025d736c6d43b372f4dea77bf75b8/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string5 = /319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string6 = /50941ad9fd99db6fca5debc3c89b3e899a9527d7/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string7 = /605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string8 = /654c673c177a2a06c2b240ee07f81dc9096b1626f82855dc67722a5e10bbf6a1/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string9 = /654c673c177a2a06c2b240ee07f81dc9096b1626f82855dc67722a5e10bbf6a1/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string10 = /7de9505c6a9be2ff8b308140d28e9318a6045529f70a48bd7ce4115d263988cb/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string11 = /86fc2c94f8fa3938e3261d0b9eb4836be289f8ae/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string12 = /91ae5ce613fa82b7764401fb12fb8977a0b3c78325faa16f30abeb3dfbe9c71a/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string13 = /b83ee6d62e5e159fa0a16fcad953862a1d567abc5c60aa35dc02aac7efc87870/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string14 = /b83ee6d62e5e159fa0a16fcad953862a1d567abc5c60aa35dc02aac7efc87870/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise
        // Reference: https://securelist.com/xz-backdoor-story-part-1/112354/
        $string15 = /c86c8f8a69c07fbec8dd650c6604bf0c9876261f/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string16 = /d2d99c2dcb17923e9ce1d91e16491527edcdd945aa68e54d83bc6fc927274b05/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string17 = /d2d99c2dcb17923e9ce1d91e16491527edcdd945aa68e54d83bc6fc927274b05/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string18 = /d44d0425769fa2e0b6875e5ca25d45b251bbe98870c6b9bef34f7cea9f84c9c3/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string19 = /d44d0425769fa2e0b6875e5ca25d45b251bbe98870c6b9bef34f7cea9f84c9c3/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://x.com/cyb3rops/status/1776924344481984944
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string20 = /ece869c6e359a650da3a82c8d26239bde4293a591c0d634815595129654665ae/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string21 = /ece869c6e359a650da3a82c8d26239bde4293a591c0d634815595129654665ae/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string22 = /eval\s\$zrKcKQ/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string23 = /ffcd092a7d9ec7d79a115e3e98f4509bee3e3977e401967140e2e5de061f8a0b/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: @cyb3rops - link: https://github.com/Neo23x0/signature-base/blob/07daba7eb7bc44e6f73e199c6b9892241ab1b3d7/yara/bkdr_xz_util_cve_2024_3094.yar#L2
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string24 = /G1Q\+4a0TgAHnlq2B8BKLZUP6wDHsjX6F5nVtUTU3dBQ/ nocase ascii wide
        // Description: backdoor in upstream xz/liblzma leading to ssh server compromise - rule author: Elastic Security - link: https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Linux_Trojan_XZBackdoor.yar
        // Reference: https://www.openwall.com/lists/oss-security/2024/03/29/4
        $string25 = /yolAbejyiejuvnup\=Evjtgvsh5okmkAvj/ nocase ascii wide

    condition:
        any of them
}
