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
        $string1 = /\[\+\]\sConnected\sto\s\\\\\\\\.{0,1000}\\\\IPC\$/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string2 = /\[\+\]\sPipe\slisting\:/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string3 = /70BCFFDB\-AE25\-4BEA\-BF0E\-09DF06B7DBC4/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string4 = /beacon_command_detail\(\"remotepipelist\"/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string5 = /List\sthe\snamed\spipes\son\sa\sremote\ssystem/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string6 = /namespace\sRemotePipeList/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string7 = /outflank_stage1\.implant/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string8 = /remotepipelist\s/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string9 = /RemotePipeList\sis\sx64\sonly/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string10 = /RemotePipeList\.cna/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string11 = /RemotePipeList\.exe/ nocase ascii wide
        // Description: A small tool that can list the named pipes bound on a remote system.
        // Reference: https://github.com/outflanknl/C2-Tool-Collection/tree/main/Other/RemotePipeList
        $string12 = /stage1\-remotepipelist\.py/ nocase ascii wide

    condition:
        any of them
}
