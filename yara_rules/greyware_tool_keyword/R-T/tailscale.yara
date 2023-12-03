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
        $string1 = /.{0,1000}\sinstall\stailscale.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string2 = /.{0,1000}\snet\-vpn\/tailscale.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string3 = /.{0,1000}\stailscale\.exe.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string4 = /.{0,1000}\stailscale\-archive\-keyring.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string5 = /.{0,1000}\.tailscale\-keyring\.list.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string6 = /.{0,1000}\/cmd\/tailscaled.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string7 = /.{0,1000}\/sources\.list\.d\/tailscale\.list.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string8 = /.{0,1000}\/tailscale\supdate.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string9 = /.{0,1000}\/tailscale\.exe.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string10 = /.{0,1000}\/tailscale\/cli\/.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string11 = /.{0,1000}\/tailscale\/client\/.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string12 = /.{0,1000}\/tailscale\/clientupdate\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string13 = /.{0,1000}\/tailscale:unstable.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string14 = /.{0,1000}\/tailscale_.{0,1000}_.{0,1000}\.deb.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string15 = /.{0,1000}\/tailscale_.{0,1000}_.{0,1000}\.tgz.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string16 = /.{0,1000}\/tailscaled\.defaults.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string17 = /.{0,1000}\/tailscaled\.go.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string18 = /.{0,1000}\/tailscaled\.sock.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string19 = /.{0,1000}\/tailscale\-setup\-.{0,1000}\-.{0,1000}\.msi.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string20 = /.{0,1000}\/tailscale\-setup\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string21 = /.{0,1000}\/test_tailscale\.sh.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string22 = /.{0,1000}\\\\\.\\pipe\\tailscale\-test.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string23 = /.{0,1000}\\cmd\\tailscaled.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string24 = /.{0,1000}\\tailscale\.exe.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string25 = /.{0,1000}\\tailscale\\cli\\.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string26 = /.{0,1000}\\tailscale\\client\\.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string27 = /.{0,1000}\\tailscale\\clientupdate\\.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string28 = /.{0,1000}\\tailscale\\cmd\\.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string29 = /.{0,1000}\\tailscale_.{0,1000}_.{0,1000}\.deb.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string30 = /.{0,1000}\\tailscale_.{0,1000}_.{0,1000}\.tgz.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string31 = /.{0,1000}\\tailscaled\.go.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string32 = /.{0,1000}\\tailscale\-setup\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string33 = /.{0,1000}\\test_tailscale\.sh.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string34 = /.{0,1000}\<h1\>Hello\sfrom\sTailscale\<\/h1\>.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string35 = /.{0,1000}apk\sadd\stailscale.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string36 = /.{0,1000}cmd\/tailscale.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string37 = /.{0,1000}connected\svia\stailscaled.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string38 = /.{0,1000}EnableTailscaleDNSSettings.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string39 = /.{0,1000}EnableTailscaleSubnets.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string40 = /.{0,1000}github\.com\/tailscale.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string41 = /.{0,1000}http:\/\/127\.0\.0\.1:4000.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string42 = /.{0,1000}http:\/\/local\-tailscaled\.sock.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string43 = /.{0,1000}https:\/\/api\.tailscale\.com\/api\/v2\/.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string44 = /.{0,1000}https:\/\/apps\.apple\.com\/us\/app\/tailscale\/id.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string45 = /.{0,1000}https:\/\/login\.tailscale\.com\/admin\/settings\/keys.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string46 = /.{0,1000}https:\/\/tailscale\.com\/s\/resolvconf\-overwrite.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string47 = /.{0,1000}install\s\-y\stailscale.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string48 = /.{0,1000}linuxfw\.TailscaleSubnetRouteMark.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string49 = /.{0,1000}local\-tailscaled\.sock.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string50 = /.{0,1000}login\.tailscale\.com.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string51 = /.{0,1000}pacman\s\-S\stailscale.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string52 = /.{0,1000}pkgctl\-Tailscale\.service.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string53 = /.{0,1000}pkgs\.tailscale\.com\/.{0,1000}\/.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string54 = /.{0,1000}rc\-update\sadd\stailscale.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string55 = /.{0,1000}resolv\.pre\-tailscale\-backup\.conf.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string56 = /.{0,1000}resolv\.tailscale\.conf.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string57 = /.{0,1000}service\stailscaled\s.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string58 = /.{0,1000}Serving\sTailscale\sweb\sclient\son\shttp:\/\/.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string59 = /.{0,1000}Starting\stailscaled.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string60 = /.{0,1000}sudo\stailscale\sup.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string61 = /.{0,1000}systemctl\senable\s\-\-now\stailscaled.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string62 = /.{0,1000}tailscale\sip\s\-4.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string63 = /.{0,1000}Tailscale\sis\snot\srunning.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string64 = /.{0,1000}tailscale\sping\s\-.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string65 = /.{0,1000}tailscale\sserve\s\-.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string66 = /.{0,1000}tailscale\sset\s\-\-auto\-update.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string67 = /.{0,1000}Tailscale\sSSH\sis\s.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string68 = /.{0,1000}tailscale\sup\s\-\-login\-server\=.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string69 = /.{0,1000}Tailscale\swas\salready\sstopped.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string70 = /.{0,1000}tailscale\.com\/install\.sh.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string71 = /.{0,1000}tailscale\.com\/logger\.Logf.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string72 = /.{0,1000}tailscale\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string73 = /.{0,1000}tailscale\/go\/releases\/download\/.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string74 = /.{0,1000}tailscale\/net\/dns\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string75 = /.{0,1000}tailscale\/tailscale\.go.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string76 = /.{0,1000}tailscale\\net\\dns.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string77 = /.{0,1000}tailscale\\scripts\\installer\.sh.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string78 = /.{0,1000}tailscale\\tailscale\.go.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string79 = /.{0,1000}Tailscaled\sexited.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string80 = /.{0,1000}tailscaled\.exe.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string81 = /.{0,1000}tailscaled\.log.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string82 = /.{0,1000}tailscaled\.openrc.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string83 = /.{0,1000}tailscaled\.sh.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string84 = /.{0,1000}tailscaled\.stdout\.log.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string85 = /.{0,1000}tailscaled_notwindows\.go.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string86 = /.{0,1000}tailscale\-ipn\.exe.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string87 = /.{0,1000}tailscale\-ipn\.log\.conf.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string88 = /.{0,1000}tailscale\-setup\-.{0,1000}\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string89 = /.{0,1000}tailscale\-setup\-full\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string90 = /.{0,1000}Updating\sTailscale\sfrom\s.{0,1000}/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string91 = /.{0,1000}yum\.repos\.d\/tailscale\.repo.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
