rule SocialPwned
{
    meta:
        description = "Detection patterns for the tool 'SocialPwned' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SocialPwned"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string1 = /\/lib\/GHunt\// nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string2 = /\/PwnDB\.py/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string3 = /\/SocialPwned/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string4 = /SocialPwned\.git/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string5 = /socialpwned\.py/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string6 = /socialpwned_.{0,1000}\.txt/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string7 = /\-\-tor\-proxy.{0,1000}\-\-pwndb/ nocase ascii wide

    condition:
        any of them
}
