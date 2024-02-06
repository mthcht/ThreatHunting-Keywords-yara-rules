rule TokenStealer
{
    meta:
        description = "Detection patterns for the tool 'TokenStealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string1 = /\.exe\s\-u\s.{0,1000}\s\-s\s2\s\-c\scmd\.exe/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string2 = /\/TokenStealer\.git/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string3 = /\[\+\]\sMy\spersonal\ssimple\sand\sstupid\s\sToken\sStealer\.\.\.\s/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string4 = /\[\+\]\sv1\.0\s\@decoder_it\s2023/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string5 = /\]\sToken\sdoes\sNOT\shave\sSE_ASSIGN_PRIMARY_NAME.{0,1000}\susing\sCreateProcessAsWithToken\(\)\sfor\slaunching\:/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string6 = /\<SessionId\>\:\slist\/steal\stoken\sfrom\sspecific\ssession/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string7 = /ABC32DBD\-B697\-482D\-A763\-7BA82FE9CEA2/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string8 = /decoder\-it\/TokenStealer/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string9 = /list\/steal\stoken\sof\suser\s\<user\>.{0,1000}default\sNT\sAUTHORITY\\\\SYSTEM\sfor\scomamnd\sexecution/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string10 = /\-t\:\sforce\suse\sof\sImpersonation\sPrivilege/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string11 = /TokenStealer\.cpp/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string12 = /TokenStealer\.exe/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string13 = /TokenStealer\.sln/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string14 = /TokenStealer\.vcxproj/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string15 = /TokenStealer\-master/ nocase ascii wide

    condition:
        any of them
}
