rule NetRipper
{
    meta:
        description = "Detection patterns for the tool 'NetRipper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetRipper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string1 = /\sNetRipper\.dll/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string2 = /\.DLL\sinjection\scomplete\!/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string3 = /\.exe\s\-w\s.{0,1000}\.dll\s\-l\sTEMP\s\-p\strue\s\-d\s4096\s\-s\suser\,pass/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string4 = /\/NetRipper\.dll/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string5 = /\/NetRipper\.exe/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string6 = /\/NetRipper\.git/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string7 = /\/NetRipper\.x64\.exe/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string8 = /\/NetRipper\.x86\.exe/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string9 = /\/NetRipperLog\.txt/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string10 = /\/windows\/gather\/netripper/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string11 = /\\InjectedDLL\.cpp/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string12 = /\\NetRipper\.cpp/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string13 = /\\NetRipper\.dll/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string14 = /\\NetRipper\.exe/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string15 = /\\netripper\.rb/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string16 = /\\NetRipper\.sln/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string17 = /\\NetRipper\.x64\.exe/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string18 = /\\NetRipper\.x64\.pdb/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string19 = /\\NetRipper\.x86\.exe/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string20 = /\\NetRipper\.x86\.pdb/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string21 = /\\NetRipperLog\.txt/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string22 = /\<\/NetRipper\>/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string23 = /027FAC75\-3FDB\-4044\-8DD0\-BC297BD4C461/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string24 = /027FAC75\-3FDB\-4044\-8DD0\-BC297BD4C461/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string25 = /027FAC75\-3FDB\-4044\-8DD0\-BC297BD4C461/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string26 = /027FAC75\-3FDB\-4044\-8DD0\-BC297BD4C461/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string27 = /027FAC75\-3FDB\-4044\-8DD0\-BC297BD4C461/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string28 = /1f4b9fe826113f8139be95e894e033044d0ddd185f9a2f30fcf213852f007790/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string29 = /32201855814f2d6df4a5803a8eb182fe10e401da90fdbf67c2318c523b4fd619/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string30 = /36AB45D2\-F886\-4803\-AA7E\-6FD5520458FC/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string31 = /438dbddd65bd3110fe61ebe3266d1cb441ea25dfc13cb626c076203e5721244d/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string32 = /4de892d30281aac34dd5aeb710d6fffc90e46b7d9df8505205531afe991973f4/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string33 = /55d11ca1d51a951627e693d7c26536528c24afd46ea7a1f8bf99907066f62ed4/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string34 = /60BBE2CB\-585B\-4DBD\-9CB9\-22F00D3F11E5/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string35 = /8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABl4ZX1IYD7piGA/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string36 = /9a8e6eed94ace0f4d3b91c7a8eb44625aaeb777c757cb262b22591c0f6253449/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string37 = /becb807e8d5a4508b1ea3e4e8ab5af60fd5dcfc4e938a58c1694cc968aab521a/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string38 = /c3e1e5a3e7b7e2d270582b233f94888de48d37642b9a6cdc019d2703aa1e4f0c/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string39 = /F142A341\-5EE0\-442D\-A15F\-98AE9B48DBAE/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string40 = /F142A341\-5EE0\-442D\-A15F\-98AE9B48DBAE/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string41 = /F142A341\-5EE0\-442D\-A15F\-98AE9B48DBAE/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string42 = /F142A341\-5EE0\-442D\-A15F\-98AE9B48DBAE/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string43 = /F142A341\-5EE0\-442D\-A15F\-98AE9B48DBAE/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string44 = /Injecting\sNetRipper\sinto\sprocess\swith\sID\s/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string45 = /Invoke\-NetRipper/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string46 = /Invoke\-\-Shellcode\.ps1/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string47 = /local\:Invoke\-PatchDll/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string48 = /NetRipper\sDLL\s\(32\sbits\)\ssuccessfully\scompiled/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string49 = /NetRipper\sDLL\s\(64\sbits\)\ssuccessfully\scompiled/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string50 = /NytroRST\/NetRipper/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string51 = /Patching\sNetRipper\sDLL/ nocase ascii wide
        // Description: NetRipper - Smart traffic sniffing for penetration testers
        // Reference: https://github.com/NytroRST/NetRipper
        $string52 = /\'S\'\,\'e\'\,\'l\'\,\'f\'\,\'R\'\,\'e\'\,\'f\'\,\'l\'\,\'e\'\,\'c\'\,\'t\'\,\'i\'\,\'v\'\,\'e\'/ nocase ascii wide

    condition:
        any of them
}
