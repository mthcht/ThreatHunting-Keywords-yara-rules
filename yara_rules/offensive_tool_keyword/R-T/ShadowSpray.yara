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
        $string1 = /.{0,1000}\s\-\sShadowSpray.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string2 = /.{0,1000}\/ShadowSpray\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string3 = /.{0,1000}\/ShadowSpray\/.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string4 = /.{0,1000}\[\+\]\sAttack\saborted\.\sExiting.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string5 = /.{0,1000}\\ShadowSpray\\.{0,1000}\.cs.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string6 = /.{0,1000}7E47D586\-DDC6\-4382\-848C\-5CF0798084E1.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string7 = /.{0,1000}CN\=ShadowSpray.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string8 = /.{0,1000}Performing\srecursive\sShadowSpray\sattack.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string9 = /.{0,1000}ShadowSpray\srecovered.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string10 = /.{0,1000}ShadowSpray\.Asn1.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string11 = /.{0,1000}ShadowSpray\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string12 = /.{0,1000}ShadowSpray\.Kerb.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string13 = /.{0,1000}ShadowSpray\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string14 = /.{0,1000}ShadowSpray\-master.{0,1000}/ nocase ascii wide
        // Description: A tool to spray Shadow Credentials across an entire domain in hopes of abusing long forgotten GenericWrite/GenericAll DACLs over other objects in the domain.
        // Reference: https://github.com/ShorSec/ShadowSpray
        $string15 = /.{0,1000}ShorSec\/ShadowSpray.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
