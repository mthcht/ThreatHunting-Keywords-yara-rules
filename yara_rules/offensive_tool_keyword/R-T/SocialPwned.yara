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
        $string1 = /.{0,1000}\/lib\/GHunt\/.{0,1000}/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string2 = /.{0,1000}\/PwnDB\.py.{0,1000}/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string3 = /.{0,1000}\/SocialPwned.{0,1000}/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string4 = /.{0,1000}SocialPwned\.git.{0,1000}/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string5 = /.{0,1000}socialpwned\.py.{0,1000}/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string6 = /.{0,1000}socialpwned_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: SocialPwned is an OSINT tool that allows to get the emails. from a target. published in social networks like Instagram. Linkedin and Twitter to find the possible credential leaks in PwnDB or Dehashed and obtain Google account information via GHunt.
        // Reference: https://github.com/MrTuxx/SocialPwned
        $string7 = /.{0,1000}\-\-tor\-proxy.{0,1000}\-\-pwndb.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
