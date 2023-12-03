rule RemotePipeList
{
    meta:
        description = "Detection patterns for the tool 'RemotePipeList' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemotePipeList"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string1 = /.{0,1000}\[\+\]\sConnected\sto\s\\\\\\\\.{0,1000}\\\\IPC\$.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string2 = /.{0,1000}\[\+\]\sPipe\slisting:.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string3 = /.{0,1000}70BCFFDB\-AE25\-4BEA\-BF0E\-09DF06B7DBC4.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string4 = /.{0,1000}beacon_command_detail\(\"remotepipelist\".{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string5 = /.{0,1000}List\sthe\snamed\spipes\son\sa\sremote\ssystem.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string6 = /.{0,1000}namespace\sRemotePipeList.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string7 = /.{0,1000}outflank_stage1\.implant.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string8 = /.{0,1000}remotepipelist\s.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string9 = /.{0,1000}RemotePipeList\sis\sx64\sonly.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string10 = /.{0,1000}RemotePipeList\.cna.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string11 = /.{0,1000}RemotePipeList\.exe.{0,1000}/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string12 = /.{0,1000}stage1\-remotepipelist\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
