rule KrbRelay
{
    meta:
        description = "Detection patterns for the tool 'KrbRelay' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrbRelay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\sasktgt\s\/user\:\{0\}\s\/certificate\:\{1\}\s\/password\:\"\{2\}\"\s/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string2 = /\s\-spn\scifs.{0,1000}\s\-session\s.{0,1000}\s\-clsid\s.{0,1000}\s\-secrets/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string3 = /\/CheckPort\.exe/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string4 = /\/KrbRelay/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\/KrbRelay\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string6 = /\\KrbRelay\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string7 = /\>KrbRelay\</ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string8 = /CheckPort\.csproj/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string9 = /KrbRelay\sby\s\@Cube0x0/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string10 = /KrbRelay.{0,1000}misc/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string11 = /KrbRelay.{0,1000}smb/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string12 = /KrbRelay.{0,1000}spoofing/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string13 = /KrbRelay\.csproj/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string14 = /KrbRelay\.exe\s/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string15 = /KrbRelay\.exe/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string16 = /KrbRelay\.sln/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string17 = /\-llmnr\s\-spn\s\'.{0,1000}cifs.{0,1000}\s\-secrets/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string18 = /OleViewDotNet\.psd1/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string19 = /\-spn\s.{0,1000}\s\-clsid\s.{0,1000}\s\-shadowcred/ nocase ascii wide

    condition:
        any of them
}
