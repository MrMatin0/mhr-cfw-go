package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/denuitt1/mhr-cfw/internal/cert"
	"github.com/denuitt1/mhr-cfw/internal/config"
	"github.com/denuitt1/mhr-cfw/internal/constants"
	"github.com/denuitt1/mhr-cfw/internal/lan"
	"github.com/denuitt1/mhr-cfw/internal/logging"
	"github.com/denuitt1/mhr-cfw/internal/mitm"
	"github.com/denuitt1/mhr-cfw/internal/proxy"
	"github.com/denuitt1/mhr-cfw/internal/scanner"
	"github.com/denuitt1/mhr-cfw/internal/setup"
	"github.com/denuitt1/mhr-cfw/internal/tui"
)

// placeholderAuthKeys is the set of values that are considered unset/insecure.
var placeholderAuthKeys = map[string]bool{
	"":                             true,
	"changeme":                     true,
	"CHANGE_ME_TO_A_STRONG_SECRET": true,
	"your-secret-password-here":    true,
}

type args struct {
	configPath    string
	port          int
	host          string
	socksPort     int
	disableSocks  bool
	logLevel      string
	installCert   bool
	uninstallCert bool
	noCertCheck   bool
	scan          bool
}

func parseArgs() (*args, bool, error) {
	a := &args{}
	flag.StringVar(&a.configPath, "config", envOr("DFT_CONFIG", "config.json"), "path to config file")
	flag.IntVar(&a.port, "port", 0, "override listen port")
	flag.StringVar(&a.host, "host", "", "override listen host")
	flag.IntVar(&a.socksPort, "socks5-port", 0, "override SOCKS5 port")
	flag.BoolVar(&a.disableSocks, "disable-socks5", false, "disable SOCKS5 listener")
	flag.StringVar(&a.logLevel, "log-level", "", "log level (DEBUG, INFO, WARN, ERROR)")
	flag.BoolVar(&a.installCert, "install-cert", false, "install MITM CA and exit")
	flag.BoolVar(&a.uninstallCert, "uninstall-cert", false, "remove MITM CA and exit")
	flag.BoolVar(&a.noCertCheck, "no-cert-check", false, "skip certificate trust check on startup")
	flag.BoolVar(&a.scan, "scan", false, "scan Google IPs and exit")

	setupFlag := flag.Bool("setup", false, "run interactive setup wizard and exit")
	noMenu := flag.Bool("no-menu", false, "run without interactive TUI menu")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mhr-cfw-go %s\n", constants.Version)
		os.Exit(0)
	}

	if *setupFlag {
		if err := setup.RunInteractiveWizard(a.configPath); err != nil {
			return nil, false, fmt.Errorf("setup: %w", err)
		}
		os.Exit(0)
	}

	// Return a flag indicating whether we should show the menu.
	showMenu := !*noMenu && isTTY(os.Stdin)
	return a, showMenu, nil
}

func main() {
	a, showMenu, err := parseArgs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	if showMenu {
		if err := runMenu(a); err != nil {
			fmt.Fprintln(os.Stderr, "menu error:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// --install-cert / --uninstall-cert as CLI flags (non-menu path).
	if a.installCert {
		logging.Configure("INFO")
		if !fileExists(mitm.CACertFile) {
			_ = mitm.NewManager()
		}
		if cert.InstallCA(mitm.CACertFile, cert.DefaultCertName) {
			fmt.Println("[OK] CA installed")
		} else {
			fmt.Fprintln(os.Stderr, "[ERR] CA install failed")
			os.Exit(1)
		}
		return
	}
	if a.uninstallCert {
		logging.Configure("INFO")
		if cert.UninstallCA(mitm.CACertFile, cert.DefaultCertName) {
			fmt.Println("[OK] CA removed")
		} else {
			fmt.Fprintln(os.Stderr, "[ERR] CA removal failed")
			os.Exit(1)
		}
		return
	}
	if a.scan {
		cfg, err := config.Load(a.configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
		logging.Configure("INFO")
		frontDomain := cfg.GetString("front_domain", "www.google.com")
		fmt.Println("Scanning — this may take a minute on slow networks.")
		if !scanner.ScanSync(frontDomain) {
			os.Exit(1)
		}
		return
	}

	// Default: run the proxy.
	if err := runProxy(a); err != nil {
		fmt.Fprintln(os.Stderr, "proxy error:", err)
		os.Exit(1)
	}
}

func runMenu(a *args) error {
	menu := &tui.Menu{
		Title: "mhr-cfw",
		Options: []tui.Option{
			{Key: 1, Label: "Start proxy", Handler: func() error { return runProxy(a) }},
			{Key: 2, Label: "Setup wizard", Handler: func() error { return setup.RunInteractiveWizard(a.configPath) }},
			{Key: 3, Label: "Install CA certificate", Handler: func() error {
				logging.Configure("INFO")
				if !fileExists(mitm.CACertFile) {
					_ = mitm.NewManager()
				}
				if cert.InstallCA(mitm.CACertFile, cert.DefaultCertName) {
					fmt.Println("[OK] CA installed")
					return nil
				}
				return errors.New("CA install failed")
			}},
			{Key: 4, Label: "Uninstall CA certificate", Handler: func() error {
				logging.Configure("INFO")
				if cert.UninstallCA(mitm.CACertFile, cert.DefaultCertName) {
					fmt.Println("[OK] CA removed")
					return nil
				}
				return errors.New("CA removal failed")
			}},
			{Key: 5, Label: "Scan Google IPs", Handler: func() error {
				cfg, err := config.Load(a.configPath)
				if err != nil {
					return err
				}
				logging.Configure("INFO")
				frontDomain := cfg.GetString("front_domain", "www.google.com")
				fmt.Println("\nScanning — this may take a minute on slow networks.")
				if !scanner.ScanSync(frontDomain) {
					return errors.New("no reachable IPs found")
				}
				return nil
			}},
			{Key: 6, Label: "Exit", Handler: nil},
		},
	}
	return menu.Run()
}

func runProxy(a *args) error {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Environment variable overrides.
	applyEnvOverrides(cfg)

	// CLI flag overrides (take precedence over env).
	if a.port != 0 {
		cfg.Set("listen_port", a.port)
	}
	if a.host != "" {
		cfg.Set("listen_host", a.host)
	}
	if a.socksPort != 0 {
		cfg.Set("socks5_port", a.socksPort)
	}
	if a.disableSocks {
		cfg.Set("socks5_enabled", false)
	}
	if a.logLevel != "" {
		cfg.Set("log_level", a.logLevel)
	}

	// Validate required fields before starting.
	authKey := strings.TrimSpace(cfg.GetString("auth_key", ""))
	if placeholderAuthKeys[authKey] {
		return errors.New("refusing to start: auth_key is unset or placeholder — edit config.json")
	}

	cfg.Set("mode", "apps_script")
	sid := cfg.GetScriptID()
	if sid == "" || sid == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID" || sid == "changeme" {
		return errors.New("refusing to start: script_id is unset — edit config.json")
	}

	logging.Configure(cfg.GetString("log_level", "INFO"))
	log := logging.Get("Main")
	logging.PrintBanner(constants.Version)
	log.Infof("DomainFront Tunnel starting (Apps Script relay)")
	log.Infof("Apps Script relay : SNI=%s -> script.google.com", cfg.GetString("front_domain", "www.google.com"))

	if ids := cfg.GetScriptIDs(); len(ids) > 1 {
		log.Infof("Script IDs        : %d scripts (sticky per-host)", len(ids))
		for i, id := range ids {
			log.Infof("  [%d] %s", i+1, id)
		}
	} else if len(ids) == 1 {
		log.Infof("Script ID         : %s", ids[0])
	}

	// Ensure CA exists before checking trust.
	if !fileExists(mitm.CACertFile) {
		_ = mitm.NewManager()
	}
	if !a.noCertCheck {
		if !cert.IsCATrusted(mitm.CACertFile, cert.DefaultCertName) {
			log.Warnf("MITM CA is not trusted — attempting automatic installation...")
			if cert.InstallCA(mitm.CACertFile, cert.DefaultCertName) {
				log.Infof("CA certificate installed. You may need to restart your browser.")
			} else {
				log.Errorf("Auto-install failed. Run with --install-cert or install ca/ca.crt manually.")
			}
		} else {
			log.Infof("MITM CA is already trusted.")
		}
	}

	// LAN sharing: widen listen host if needed.
	lanSharing := cfg.GetBool("lan_sharing", false)
	listenHost := cfg.GetString("listen_host", "127.0.0.1")
	if lanSharing && listenHost == "127.0.0.1" {
		cfg.Set("listen_host", "0.0.0.0")
		listenHost = "0.0.0.0"
		log.Infof("LAN sharing enabled — listening on all interfaces")
	}

	lanMode := lanSharing || listenHost == "0.0.0.0" || listenHost == "::"
	if lanMode {
		var socksPort *int
		if cfg.GetBool("socks5_enabled", true) {
			p := cfg.GetInt("socks5_port", 1080)
			socksPort = &p
		}
		lan.LogLANAccess(cfg.GetInt("listen_port", 8080), socksPort)
	}

	server, err := proxy.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Fprintf(os.Stderr, "\nReceived %v, shutting down...\n", sig)
		signal.Stop(sigs)
		cancel()

		// Force-exit if graceful shutdown takes too long.
		go func() {
			time.Sleep(5 * time.Second)
			fmt.Fprintln(os.Stderr, "Force exit after timeout")
			os.Exit(1)
		}()
	}()

	err = server.Start(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	log.Infof("Stopped cleanly")
	return nil
}

// applyEnvOverrides reads environment variables and applies them to cfg.
func applyEnvOverrides(cfg config.Config) {
	if v := os.Getenv("DFT_AUTH_KEY"); v != "" {
		cfg.Set("auth_key", v)
	}
	if v := os.Getenv("DFT_SCRIPT_ID"); v != "" {
		cfg.Set("script_id", v)
	}
	if v := os.Getenv("DFT_PORT"); v != "" {
		cfg.Set("listen_port", config.ToInt(v, cfg.GetInt("listen_port", 8080)))
	}
	if v := os.Getenv("DFT_HOST"); v != "" {
		cfg.Set("listen_host", v)
	}
	if v := os.Getenv("DFT_SOCKS5_PORT"); v != "" {
		cfg.Set("socks5_port", config.ToInt(v, cfg.GetInt("socks5_port", 1080)))
	}
	if v := os.Getenv("DFT_LOG_LEVEL"); v != "" {
		cfg.Set("log_level", v)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// configDir returns the directory containing the executable.
// Useful for resolving relative config paths.
func configDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// Ensure configDir is used (avoids "declared and not used" if callers are removed).
var _ = configDir
