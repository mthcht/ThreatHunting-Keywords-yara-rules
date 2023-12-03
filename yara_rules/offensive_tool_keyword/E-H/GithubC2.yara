rule GithubC2
{
    meta:
        description = "Detection patterns for the tool 'GithubC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GithubC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string1 = /.{0,1000}\/GithubC2\.git.{0,1000}/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string2 = /.{0,1000}\\Implant\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string3 = /.{0,1000}29446C11\-A1A5\-47F6\-B418\-0D699C6C3339.{0,1000}/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string4 = /.{0,1000}AbuseGithubAPI.{0,1000}\.cpp.{0,1000}/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string5 = /.{0,1000}AbuseGithubAPI.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string6 = /.{0,1000}F3C62326\-E221\-4481\-AC57\-EF7F76AAF27B.{0,1000}/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string7 = /.{0,1000}GithubC2\-main.{0,1000}/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string8 = /.{0,1000}TeamServer\.exe\s.{0,1000}github\.com.{0,1000}/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string9 = /.{0,1000}TheD1rkMtr\/GithubC2.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
