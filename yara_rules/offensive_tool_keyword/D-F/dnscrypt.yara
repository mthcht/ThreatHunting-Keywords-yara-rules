rule dnscrypt
{
    meta:
        description = "Detection patterns for the tool 'dnscrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string1 = /.{0,1000}\sdnscrypt\-proxy.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string2 = /.{0,1000}\sinstall\sdnscrypt\-proxy.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string3 = /.{0,1000}\srestart\sdnscrypt\-proxy.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string4 = /.{0,1000}\/dnscrypt\-proxy.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string5 = /.{0,1000}\/dnscrypt\-proxy\.git.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string6 = /.{0,1000}\/opt\/dnscrypt\-proxy.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string7 = /.{0,1000}\\dnscrypt\-proxy.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string8 = /.{0,1000}AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string9 = /.{0,1000}DNSCrypt\sclient\sproxy.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string10 = /.{0,1000}DNSCrypt\/dnscrypt\-proxy.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string11 = /.{0,1000}dnscrypt\-autoinstall.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string12 = /.{0,1000}dnscrypt\-proxy\s\-resolve.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string13 = /.{0,1000}dnscrypt\-proxy\s\-service.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string14 = /.{0,1000}dnscryptproxy\.exe.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string15 = /.{0,1000}dnscrypt\-proxy\.exe.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string16 = /.{0,1000}dnscrypt\-proxy\.socket.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string17 = /.{0,1000}dnscrypt\-proxy\.toml.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string18 = /.{0,1000}dnscrypt\-proxy\-android_arm\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string19 = /.{0,1000}dnscrypt\-proxy\-android_arm64\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string20 = /.{0,1000}dnscrypt\-proxy\-android_i386\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string21 = /.{0,1000}dnscrypt\-proxy\-android_x86_64\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string22 = /.{0,1000}dnscrypt\-proxy\-dragonflybsd_amd64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string23 = /.{0,1000}dnscrypt\-proxy\-freebsd_amd64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string24 = /.{0,1000}dnscrypt\-proxy\-freebsd_arm\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string25 = /.{0,1000}dnscrypt\-proxy\-freebsd_i386\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string26 = /.{0,1000}dnscrypt\-proxy\-linux_arm\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string27 = /.{0,1000}dnscrypt\-proxy\-linux_arm64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string28 = /.{0,1000}dnscrypt\-proxy\-linux_i386\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string29 = /.{0,1000}dnscrypt\-proxy\-linux_mips\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string30 = /.{0,1000}dnscrypt\-proxy\-linux_mips64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string31 = /.{0,1000}dnscrypt\-proxy\-linux_mips64le\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string32 = /.{0,1000}dnscrypt\-proxy\-linux_mipsle\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string33 = /.{0,1000}dnscrypt\-proxy\-linux_riscv64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string34 = /.{0,1000}dnscrypt\-proxy\-linux_x86_64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string35 = /.{0,1000}dnscrypt\-proxy\-macos_arm64\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string36 = /.{0,1000}dnscrypt\-proxy\-macos_x86_64\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string37 = /.{0,1000}dnscrypt\-proxy\-master.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string38 = /.{0,1000}dnscrypt\-proxy\-netbsd_amd64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string39 = /.{0,1000}dnscrypt\-proxy\-netbsd_i386\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string40 = /.{0,1000}dnscrypt\-proxy\-openbsd_amd64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string41 = /.{0,1000}dnscrypt\-proxy\-openbsd_i386\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string42 = /.{0,1000}dnscrypt\-proxy\-solaris_amd64\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string43 = /.{0,1000}dnscrypt\-proxy\-win32\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string44 = /.{0,1000}dnscrypt\-proxy\-win64\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string45 = /.{0,1000}dnsproxy\sstart\sscripts.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string46 = /.{0,1000}https:\/\/127\.0\.0\.1\/dns\-query.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string47 = /.{0,1000}Thank\syou\sfor\susing\sDNSCrypt\-Proxy\!.{0,1000}/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string48 = /.{0,1000}ubuntu:dnscrypt\-msi.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
