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
        $string1 = /.{0,1000}\.exe\s\-u\s.{0,1000}\s\-s\s2\s\-c\scmd\.exe.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string2 = /.{0,1000}\/TokenStealer\.git.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string3 = /.{0,1000}\[\+\]\sMy\spersonal\ssimple\sand\sstupid\s\sToken\sStealer\.\.\.\s.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string4 = /.{0,1000}\[\+\]\sv1\.0\s\@decoder_it\s2023.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string5 = /.{0,1000}\]\sToken\sdoes\sNOT\shave\sSE_ASSIGN_PRIMARY_NAME.{0,1000}\susing\sCreateProcessAsWithToken\(\)\sfor\slaunching:.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string6 = /.{0,1000}\<SessionId\>:\slist\/steal\stoken\sfrom\sspecific\ssession.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string7 = /.{0,1000}ABC32DBD\-B697\-482D\-A763\-7BA82FE9CEA2.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string8 = /.{0,1000}decoder\-it\/TokenStealer.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string9 = /.{0,1000}list\/steal\stoken\sof\suser\s\<user\>.{0,1000}default\sNT\sAUTHORITY\\\\SYSTEM\sfor\scomamnd\sexecution.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string10 = /.{0,1000}\-t:\sforce\suse\sof\sImpersonation\sPrivilege.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string11 = /.{0,1000}TokenStealer\.cpp.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string12 = /.{0,1000}TokenStealer\.exe.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string13 = /.{0,1000}TokenStealer\.sln.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string14 = /.{0,1000}TokenStealer\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string15 = /.{0,1000}TokenStealer\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
