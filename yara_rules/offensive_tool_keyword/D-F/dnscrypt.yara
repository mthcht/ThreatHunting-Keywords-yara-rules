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
        $string1 = /\sdnscrypt\-proxy/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string2 = /\sinstall\sdnscrypt\-proxy/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string3 = /\srestart\sdnscrypt\-proxy/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string4 = /\/dnscrypt\-proxy/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string5 = /\/dnscrypt\-proxy\.git/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string6 = /\/opt\/dnscrypt\-proxy/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string7 = /\\dnscrypt\-proxy/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string8 = /AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string9 = /DNSCrypt\sclient\sproxy/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string10 = /DNSCrypt\/dnscrypt\-proxy/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string11 = /dnscrypt\-autoinstall/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string12 = /dnscrypt\-proxy\s\-resolve/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string13 = /dnscrypt\-proxy\s\-service/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string14 = /dnscryptproxy\.exe/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string15 = /dnscrypt\-proxy\.exe/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string16 = /dnscrypt\-proxy\.socket/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string17 = /dnscrypt\-proxy\.toml/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string18 = /dnscrypt\-proxy\-android_arm\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string19 = /dnscrypt\-proxy\-android_arm64\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string20 = /dnscrypt\-proxy\-android_i386\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string21 = /dnscrypt\-proxy\-android_x86_64\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string22 = /dnscrypt\-proxy\-dragonflybsd_amd64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string23 = /dnscrypt\-proxy\-freebsd_amd64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string24 = /dnscrypt\-proxy\-freebsd_arm\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string25 = /dnscrypt\-proxy\-freebsd_i386\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string26 = /dnscrypt\-proxy\-linux_arm\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string27 = /dnscrypt\-proxy\-linux_arm64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string28 = /dnscrypt\-proxy\-linux_i386\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string29 = /dnscrypt\-proxy\-linux_mips\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string30 = /dnscrypt\-proxy\-linux_mips64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string31 = /dnscrypt\-proxy\-linux_mips64le\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string32 = /dnscrypt\-proxy\-linux_mipsle\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string33 = /dnscrypt\-proxy\-linux_riscv64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string34 = /dnscrypt\-proxy\-linux_x86_64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string35 = /dnscrypt\-proxy\-macos_arm64\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string36 = /dnscrypt\-proxy\-macos_x86_64\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string37 = /dnscrypt\-proxy\-master/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string38 = /dnscrypt\-proxy\-netbsd_amd64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string39 = /dnscrypt\-proxy\-netbsd_i386\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string40 = /dnscrypt\-proxy\-openbsd_amd64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string41 = /dnscrypt\-proxy\-openbsd_i386\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string42 = /dnscrypt\-proxy\-solaris_amd64\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string43 = /dnscrypt\-proxy\-win32\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string44 = /dnscrypt\-proxy\-win64\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string45 = /dnsproxy\sstart\sscripts/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string46 = /https\:\/\/127\.0\.0\.1\/dns\-query/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string47 = /Thank\syou\sfor\susing\sDNSCrypt\-Proxy\!/ nocase ascii wide
        // Description: A flexible DNS proxy with support for modern encrypted DNS protocols such as DNSCrypt v2 - DNS-over-HTTPS - Anonymized DNSCrypt and ODoH (Oblivious DoH).
        // Reference: https://github.com/DNSCrypt/dnscrypt-proxy
        $string48 = /ubuntu\:dnscrypt\-msi/ nocase ascii wide

    condition:
        any of them
}
