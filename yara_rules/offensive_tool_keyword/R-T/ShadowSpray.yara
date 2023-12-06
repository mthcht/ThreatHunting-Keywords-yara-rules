rule ShadowSpray
{
    meta:
        description = "Detection patterns for the tool 'ShadowSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string1 = /\s\-\sShadowSpray/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string2 = /\/ShadowSpray\.git/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string3 = /\/ShadowSpray\/.{0,1000}\.cs/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string4 = /\[\+\]\sAttack\saborted\.\sExiting/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string5 = /\\ShadowSpray\\.{0,1000}\.cs/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string6 = /7E47D586\-DDC6\-4382\-848C\-5CF0798084E1/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string7 = /CN\=ShadowSpray/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string8 = /Performing\srecursive\sShadowSpray\sattack/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string9 = /ShadowSpray\srecovered/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string10 = /ShadowSpray\.Asn1/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string11 = /ShadowSpray\.exe/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string12 = /ShadowSpray\.Kerb/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string13 = /ShadowSpray\.sln/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string14 = /ShadowSpray\-master/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string15 = /ShorSec\/ShadowSpray/ nocase ascii wide

    condition:
        any of them
}
