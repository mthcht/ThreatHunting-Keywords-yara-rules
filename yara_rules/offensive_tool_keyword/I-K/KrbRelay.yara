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
        $string1 = /.{0,1000}\s\-spn\scifs.{0,1000}\s\-session\s.{0,1000}\s\-clsid\s.{0,1000}\s\-secrets.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string2 = /.{0,1000}\/CheckPort\.exe.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string3 = /.{0,1000}\/KrbRelay.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string4 = /.{0,1000}CheckPort\.csproj.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string5 = /.{0,1000}KrbRelay.{0,1000}misc.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string6 = /.{0,1000}KrbRelay.{0,1000}smb.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string7 = /.{0,1000}KrbRelay.{0,1000}spoofing.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string8 = /.{0,1000}KrbRelay\.csproj.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string9 = /.{0,1000}KrbRelay\.exe.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string10 = /.{0,1000}KrbRelay\.sln.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string11 = /.{0,1000}\-llmnr\s\-spn\s\'.{0,1000}cifs.{0,1000}\s\-secrets.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string12 = /.{0,1000}OleViewDotNet\.psd1.{0,1000}/ nocase ascii wide
        // Description: Relaying 3-headed dogs. More details at https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html and https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
        // Reference: https://github.com/cube0x0/KrbRelay
        $string13 = /.{0,1000}\-spn\s.{0,1000}\s\-clsid\s.{0,1000}\s\-shadowcred.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
