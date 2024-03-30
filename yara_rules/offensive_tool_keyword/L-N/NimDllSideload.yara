rule NimDllSideload
{
    meta:
        description = "Detection patterns for the tool 'NimDllSideload' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimDllSideload"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string1 = /\/dllproxy\.nim/ nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string2 = /\/NimDllSideload\.git/ nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string3 = /\/NimDllSideload\// nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string4 = /\\dllproxy\.nim/ nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string5 = /\\NimDllSideload\\/ nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string6 = /a0acc8bea0d7e8ecacd1b7545e073b7575c28ad9be6464e1e756ba63084b9cd0/ nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string7 = /app\/dllproxy\.nim/ nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string8 = /byt3bl33d3r\/NimDllSideload/ nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string9 = /make\simage\s\&\&\smake\sproxydll/ nocase ascii wide
        // Description: DLL sideloading/proxying
        // Reference: https://github.com/byt3bl33d3r/NimDllSideload
        $string10 = /NimDllSideload\-main/ nocase ascii wide

    condition:
        any of them
}
