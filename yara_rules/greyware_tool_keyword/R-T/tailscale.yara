rule tailscale
{
    meta:
        description = "Detection patterns for the tool 'tailscale' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tailscale"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string1 = /\sinstall\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string2 = /\snet\-vpn\/tailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string3 = /\stailscale\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string4 = /\stailscale\-archive\-keyring/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string5 = /\.tailscale\-keyring\.list/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string6 = /\/cmd\/tailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string7 = /\/sources\.list\.d\/tailscale\.list/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string8 = /\/tailscale\supdate/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string9 = /\/tailscale\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string10 = /\/tailscale\/cli\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string11 = /\/tailscale\/client\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string12 = /\/tailscale\/clientupdate\/.{0,1000}\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string13 = /\/tailscale\:unstable/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string14 = /\/tailscale_.{0,1000}_.{0,1000}\.deb/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string15 = /\/tailscale_.{0,1000}_.{0,1000}\.tgz/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string16 = /\/tailscaled\.defaults/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string17 = /\/tailscaled\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string18 = /\/tailscaled\.sock/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string19 = /\/tailscale\-setup\-.{0,1000}\-.{0,1000}\.msi/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string20 = /\/tailscale\-setup\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string21 = /\/test_tailscale\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string22 = /\\\\\.\\pipe\\tailscale\-test/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string23 = /\\cmd\\tailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string24 = /\\tailscale\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string25 = /\\tailscale\\cli\\/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string26 = /\\tailscale\\client\\/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string27 = /\\tailscale\\clientupdate\\/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string28 = /\\tailscale\\cmd\\/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string29 = /\\tailscale_.{0,1000}_.{0,1000}\.deb/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string30 = /\\tailscale_.{0,1000}_.{0,1000}\.tgz/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string31 = /\\tailscaled\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string32 = /\\tailscale\-setup\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string33 = /\\test_tailscale\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string34 = /\<h1\>Hello\sfrom\sTailscale\<\/h1\>/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string35 = /apk\sadd\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string36 = /cmd\/tailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string37 = /connected\svia\stailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string38 = /EnableTailscaleDNSSettings/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string39 = /EnableTailscaleSubnets/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string40 = /github\.com\/tailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string41 = /http\:\/\/127\.0\.0\.1\:4000/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string42 = /http\:\/\/local\-tailscaled\.sock/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string43 = /https\:\/\/api\.tailscale\.com\/api\/v2\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string44 = /https\:\/\/apps\.apple\.com\/us\/app\/tailscale\/id/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string45 = /https\:\/\/login\.tailscale\.com\/admin\/settings\/keys/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string46 = /https\:\/\/tailscale\.com\/s\/resolvconf\-overwrite/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string47 = /install\s\-y\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string48 = /linuxfw\.TailscaleSubnetRouteMark/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string49 = /local\-tailscaled\.sock/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string50 = /login\.tailscale\.com/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string51 = /pacman\s\-S\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string52 = /pkgctl\-Tailscale\.service/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string53 = /pkgs\.tailscale\.com\/.{0,1000}\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string54 = /rc\-update\sadd\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string55 = /resolv\.pre\-tailscale\-backup\.conf/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string56 = /resolv\.tailscale\.conf/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string57 = /service\stailscaled\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string58 = /Serving\sTailscale\sweb\sclient\son\shttp\:\/\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string59 = /Starting\stailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string60 = /sudo\stailscale\sup/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string61 = /systemctl\senable\s\-\-now\stailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string62 = /tailscale\sip\s\-4/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string63 = /Tailscale\sis\snot\srunning/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string64 = /tailscale\sping\s\-/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string65 = /tailscale\sserve\s\-/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string66 = /tailscale\sset\s\-\-auto\-update/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string67 = /Tailscale\sSSH\sis\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string68 = /tailscale\sup\s\-\-login\-server\=/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string69 = /Tailscale\swas\salready\sstopped/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string70 = /tailscale\.com\/install\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string71 = /tailscale\.com\/logger\.Logf/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string72 = /tailscale\.exe\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string73 = /tailscale\/go\/releases\/download\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string74 = /tailscale\/net\/dns\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string75 = /tailscale\/tailscale\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string76 = /tailscale\\net\\dns/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string77 = /tailscale\\scripts\\installer\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string78 = /tailscale\\tailscale\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string79 = /Tailscaled\sexited/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string80 = /tailscaled\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string81 = /tailscaled\.log/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string82 = /tailscaled\.openrc/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string83 = /tailscaled\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string84 = /tailscaled\.stdout\.log/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string85 = /tailscaled_notwindows\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string86 = /tailscale\-ipn\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string87 = /tailscale\-ipn\.log\.conf/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string88 = /tailscale\-setup\-.{0,1000}\.exe\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string89 = /tailscale\-setup\-full\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string90 = /Updating\sTailscale\sfrom\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string91 = /yum\.repos\.d\/tailscale\.repo/ nocase ascii wide

    condition:
        any of them
}
