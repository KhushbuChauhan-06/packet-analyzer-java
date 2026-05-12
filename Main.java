package com.dpi;

import com.dpi.engine.DPIEngine;
import com.dpi.rules.RuleManager;

/**
 * Deep Packet Inspection Engine — Java port.
 *
 * Usage:
 *   java -cp out com.dpi.Main <input.pcap> <output.pcap> [options]
 *
 * Options:
 *   --block-ip   <ip>     Block all traffic from this source IP
 *   --block-app  <name>   Block application (YouTube, Facebook, TikTok, ...)
 *   --block-domain <dom>  Block domain (substring match; wildcards: *.tiktok.com)
 *   --rules <file>        Load blocking rules from a rules file
 *   --lbs <n>             Number of Load-Balancer threads  (default: 2)
 *   --fps <n>             FastPath threads per LB          (default: 2)
 *
 * Examples:
 *   java -cp out com.dpi.Main test_dpi.pcap out.pcap
 *   java -cp out com.dpi.Main test_dpi.pcap out.pcap --block-app YouTube --block-ip 192.168.1.50
 */
public class Main {

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputFile  = args[0];
        String outputFile = args[1];

        DPIEngine.Config config = new DPIEngine.Config();
        RuleManager      rules  = new RuleManager();

        // Parse CLI options
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip"     -> rules.blockIp(args[++i]);
                case "--block-app"    -> rules.blockApp(args[++i]);
                case "--block-domain" -> rules.blockDomain(args[++i]);
                case "--rules"        -> rules.loadRules(args[++i]);
                case "--lbs"          -> config.numLbs   = Integer.parseInt(args[++i]);
                case "--fps"          -> config.fpsPerLb = Integer.parseInt(args[++i]);
                case "--help", "-h"   -> { printUsage(); System.exit(0); }
                default               -> System.err.println("Unknown option: " + args[i]);
            }
        }

        DPIEngine engine = new DPIEngine(config, rules);
        boolean ok = engine.process(inputFile, outputFile);
        System.exit(ok ? 0 : 1);
    }

    private static void printUsage() {
        System.out.println("""
╔══════════════════════════════════════════════════════════════╗
║         DPI ENGINE v2.0 — Java Deep Packet Inspection        ║
╚══════════════════════════════════════════════════════════════╝

Usage:
  java -cp out com.dpi.Main <input.pcap> <output.pcap> [options]

Options:
  --block-ip   <ip>       Block source IP
  --block-app  <name>     Block application (YouTube, Facebook, TikTok …)
  --block-domain <dom>    Block domain substring (*.tiktok.com)
  --rules  <file>         Load rules from file
  --lbs  <n>              Load-Balancer threads  (default: 2)
  --fps  <n>              FastPath threads / LB  (default: 2)

Supported app names:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Examples:
  java -cp out com.dpi.Main capture.pcap filtered.pcap
  java -cp out com.dpi.Main capture.pcap filtered.pcap --block-app YouTube
  java -cp out com.dpi.Main capture.pcap filtered.pcap \\
       --block-app TikTok --block-ip 192.168.1.50 --block-domain facebook
""");
    }
}