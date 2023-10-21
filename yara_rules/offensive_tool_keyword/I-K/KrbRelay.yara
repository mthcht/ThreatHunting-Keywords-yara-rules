rule KrbRelay
{
    meta:
        description = "Detection patterns for the tool 'KrbRelay' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrbRelay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string1 = /\s\-spn\scifs.*\s\-session\s.*\s\-clsid\s.*\s\-secrets/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string2 = /\/CheckPort\.exe/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string3 = /\/KrbRelay/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string4 = /CheckPort\.csproj/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string5 = /KrbRelay.*misc/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string6 = /KrbRelay.*smb/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string7 = /KrbRelay.*spoofing/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string8 = /KrbRelay\.csproj/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string9 = /KrbRelay\.exe/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string10 = /KrbRelay\.sln/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string11 = /\-llmnr\s\-spn\s\'.*cifs.*\s\-secrets/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string12 = /OleViewDotNet\.psd1/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string13 = /\-spn\s.*\s\-clsid\s.*\s\-shadowcred/ nocase ascii wide

    condition:
        any of them
}