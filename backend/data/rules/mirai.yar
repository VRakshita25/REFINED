rule Mirai_Botnet_ELF {
    meta:
        description  = "Detects Mirai botnet ELF binaries"
        family       = "Mirai"
        type         = "Botnet"
        threat_actor = "Unknown (open-source, many operators)"
        mitre_attack = "T1498, T1059, T1071"
        severity     = "HIGH"
        reference    = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai"

    strings:
        $s1 = "/bin/busybox" ascii
        $s2 = "MIRAI" ascii
        $s3 = "mirai" nocase ascii
        $s4 = "LZRD" ascii
        $s5 = "OWARI" ascii
        $a1 = "attack_udp_generic" ascii
        $a2 = "attack_tcp_syn" ascii
        $a3 = "attack_gre_ip" ascii
        $a4 = "attack_app_http" ascii
        $a5 = "scanner_init" ascii
        $p1 = "GET /bins/" ascii
        $p2 = ".mirai" ascii
        $x1 = "watchdog" ascii
        $x2 = "/proc/net/tcp" ascii
        $x3 = "dvrHelper" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 2MB
        and (
            2 of ($s*)
            or 2 of ($a*)
            or (1 of ($s*) and 1 of ($a*))
            or (1 of ($p*) and 1 of ($x*))
        )
}

rule Mirai_Variant_SATORI {
    meta:
        description = "Detects Satori variant of Mirai"
        family      = "Mirai/Satori"
        type        = "Botnet"
        severity    = "HIGH"
        reference   = "https://blog.netlab.360.com/warning-satori-a-new-mirai-variant-is-spreading-in-worm-style-on-port-37215-and-52869-en/"

    strings:
        $s1 = "SATORI" ascii
        $s2 = "satori" nocase ascii
        $s3 = "Hello, World" ascii
        $a1 = "attack_udp_vse" ascii
        $a2 = "attack_udp_dns" ascii

    condition:
        uint32(0) == 0x464C457F
        and 2 of them
}

rule Mirai_Variant_OKIRU {
    meta:
        description = "Detects Okiru variant targeting ARC CPUs"
        family      = "Mirai/Okiru"
        type        = "Botnet"
        severity    = "HIGH"

    strings:
        $s1 = "OKIRU" ascii
        $s2 = "okiru" nocase ascii
        $s3 = "/proc/cpuinfo" ascii

    condition:
        uint32(0) == 0x464C457F
        and 2 of them
}
