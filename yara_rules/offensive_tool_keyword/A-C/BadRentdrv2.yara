rule BadRentdrv2
{
    meta:
        description = "Detection patterns for the tool 'BadRentdrv2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadRentdrv2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string1 = /\/BadRentdrv2\.git/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string2 = /\[\!\]\sPress\sany\skey\sto\sstop\sdriver\sand\sclean\sup\sall\sPOC\sfiles\sto\savoid\sdetection\s\!/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string3 = /\\BadRentdrv2\.cpp/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string4 = /1aed62a63b4802e599bbd33162319129501d603cceeb5e1eb22fd4733b3018a3/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string5 = /727a1d04\-70f4\-4148\-9120\-d06510a62a9a/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string6 = /9165d4f3036919a96b86d24b64d75d692802c7513f2b3054b20be40c212240a5/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string7 = /BadRentdrv2\.exe/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string8 = /c80bf6d8d9a8c8f9671e8723922c89d8dd7263696f7708c0ace76ce66b947a7a/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string9 = /e4fef08ac954c5787ff0c72defb9a496d030509dd2eca2afc6ef2d9c669cca71/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string10 = /f33af2c7fab6a68954caa2271921e23eeb0e0af53370b0dcb736515bb092d8f5/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string11 = /keowu\/BadRentdrv2/ nocase ascii wide

    condition:
        any of them
}
