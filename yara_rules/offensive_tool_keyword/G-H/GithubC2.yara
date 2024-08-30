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
        $string1 = /\/GithubC2\.git/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string2 = /\\Implant\.exe\s/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string3 = /29446C11\-A1A5\-47F6\-B418\-0D699C6C3339/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string4 = /AbuseGithubAPI.{0,1000}\.cpp/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string5 = /AbuseGithubAPI.{0,1000}\.exe/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string6 = /F3C62326\-E221\-4481\-AC57\-EF7F76AAF27B/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string7 = /GithubC2\-main/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string8 = /TeamServer\.exe\s.{0,1000}github\.com/ nocase ascii wide
        // Description: Github as C2
        // Reference: https://github.com/TheD1rkMtr/GithubC2
        $string9 = /TheD1rkMtr\/GithubC2/ nocase ascii wide

    condition:
        any of them
}
