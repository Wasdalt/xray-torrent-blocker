package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v2"
)

var (
	LogFile       string
	BlockDuration int
	TorrentTag    string
	BlockMode     string
	BypassIPSet   = make(map[string]struct{})
	StorageDir    string

	SendWebhook     bool
	WaitForWebhook  bool
	WebhookTimeout  int
	WebhookURL      string
	WebhookTemplate string
	WebhookHeaders  map[string]string

	UsernameRegex        *regexp.Regexp
	DefaultUsernameRegex = `^(.+)$`

	Hostname string

	EnablePerformanceMetrics bool
)

type Config struct {
	LogFile         string            `yaml:"LogFile"`
	BlockDuration   int               `yaml:"BlockDuration"`
	TorrentTag      string            `yaml:"TorrentTag"`
	UsernameRegex   string            `yaml:"UsernameRegex"`
	BlockMode       string            `yaml:"BlockMode"`
	BypassIPS       []string          `yaml:"BypassIPS"`
	SendWebhook     bool              `yaml:"SendWebhook"`
	WaitForWebhook  bool              `yaml:"WaitForWebhook"`
	WebhookTimeout  int               `yaml:"WebhookTimeout"`
	WebhookURL      string            `yaml:"WebhookURL"`
	WebhookTemplate string            `yaml:"WebhookTemplate"`
	StorageDir      string            `yaml:"StorageDir"`
	WebhookHeaders  map[string]string `yaml:"WebhookHeaders"`
}

func LoadConfig(configPath string) error {
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var cfg Config
	err = yaml.Unmarshal(configFile, &cfg)
	if err != nil {
		return err
	}

	LogFile = cfg.LogFile
	BlockDuration = cfg.BlockDuration
	TorrentTag = cfg.TorrentTag
	SendWebhook = cfg.SendWebhook
	WaitForWebhook = cfg.WaitForWebhook
	WebhookTimeout = cfg.WebhookTimeout
	if WebhookTimeout == 0 {
		WebhookTimeout = 5
	}
	WebhookURL = cfg.WebhookURL
	WebhookHeaders = cfg.WebhookHeaders

	if cfg.UsernameRegex != "" {
		UsernameRegex, err = regexp.Compile(cfg.UsernameRegex)
	} else {
		UsernameRegex, err = regexp.Compile(DefaultUsernameRegex)
	}
	if err != nil {
		return fmt.Errorf("invalid UsernameRegex pattern: %v", err)
	}

	Hostname, err = os.Hostname()
	if cfg.BlockMode != "" {
		BlockMode = cfg.BlockMode
	} else {
		BlockMode = "iptables"
	}
	if cfg.BypassIPS != nil {
		fmt.Println("Bypass IPS list:")
		BypassIPSet = make(map[string]struct{})
		for _, ip := range cfg.BypassIPS {
			BypassIPSet[ip] = struct{}{}
			fmt.Printf("- %s\n", ip)
		}
	} else {
		BypassIPSet = make(map[string]struct{})
	}
	if WebhookHeaders == nil {
		WebhookHeaders = make(map[string]string)
	}
	if cfg.WebhookTemplate != "" {
		WebhookTemplate = cfg.WebhookTemplate
	} else {
		WebhookTemplate = `{"username":"%s","ip":"%s","server":"%s","action":"%s","duration":%d,"timestamp":"%s"}`
	}

	StorageDir = cfg.StorageDir
	if StorageDir == "" {
		StorageDir = "/opt/tblocker"
	}

	applyEnvOverrides()

	return err
}

func applyEnvOverrides() {
	if v := os.Getenv("XUI_TORRENT_WEBHOOK_ENABLE"); v == "true" {
		SendWebhook = true
	}
	if v := os.Getenv("XUI_TORRENT_WAIT_WEBHOOK"); v == "true" {
		WaitForWebhook = true
	}
	if v := os.Getenv("XUI_TORRENT_WEBHOOK_URL"); v != "" {
		WebhookURL = v
	}
	if v := os.Getenv("XUI_TORRENT_WEBHOOK_TIMEOUT"); v != "" {
		if timeout, err := strconv.Atoi(v); err == nil {
			WebhookTimeout = timeout
		}
	}
	if v := os.Getenv("XUI_TORRENT_BAN_DURATION"); v != "" {
		if duration, err := strconv.Atoi(v); err == nil {
			BlockDuration = duration
		}
	}
	if v := os.Getenv("XUI_TORRENT_LOG_FILE"); v != "" {
		LogFile = v
	}
	if v := os.Getenv("XUI_TORRENT_BLOCK_MODE"); v != "" {
		BlockMode = v
	}
	if v := os.Getenv("XUI_TORRENT_STORAGE_DIR"); v != "" {
		StorageDir = v
	}
}
