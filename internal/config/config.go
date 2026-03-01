package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration for the AIBBP platform.
type Config struct {
	API          APIConfig          `mapstructure:"api"`
	Budget       BudgetConfig       `mapstructure:"budget"`
	Scanning     ScanConfig         `mapstructure:"scanning"`
	Preprocessor PreprocessorConfig `mapstructure:"preprocessor"`
	Database     DBConfig           `mapstructure:"database"`
	Redis        RedisConfig        `mapstructure:"redis"`
	NATS         NATSConfig         `mapstructure:"nats"`
	Run          RunConfig          `mapstructure:"run"`
	Logging      LogConfig          `mapstructure:"logging"`
}

// APIConfig holds Anthropic API settings.
type APIConfig struct {
	Models     ModelConfig    `mapstructure:"models"`
	RateLimits APIRateConfig  `mapstructure:"rate_limits"`
	Defaults   DefaultsConfig `mapstructure:"defaults"`
}

type ModelConfig struct {
	Routine  string `mapstructure:"routine"`  // Haiku - 80% of calls
	Complex  string `mapstructure:"complex"`  // Sonnet - 18% of calls
	Critical string `mapstructure:"critical"` // Opus - 2% of calls
}

type APIRateConfig struct {
	RequestsPerMinute     int     `mapstructure:"requests_per_minute"`
	InputTokensPerMinute  int     `mapstructure:"input_tokens_per_minute"`
	MaxRetries            int     `mapstructure:"max_retries"`
	BaseRetryDelaySeconds float64 `mapstructure:"base_retry_delay_seconds"`
}

type DefaultsConfig struct {
	Temperature          float64 `mapstructure:"temperature"`
	WordlistTemperature  float64 `mapstructure:"wordlist_temperature"`
	MaxTokens            int     `mapstructure:"max_tokens"`
	ThinkingType         string  `mapstructure:"thinking_type"`
}

// BudgetConfig controls token spending.
type BudgetConfig struct {
	TotalDollars         float64              `mapstructure:"total_dollars"`
	EmergencyReservePct  int                  `mapstructure:"emergency_reserve_pct"`
	PhaseAllocation      PhaseAllocationConfig `mapstructure:"phase_allocation"`
	PerTargetMaxDollars  float64              `mapstructure:"per_target_max_dollars"`
	Pricing              PricingConfig        `mapstructure:"pricing"`
}

type PhaseAllocationConfig struct {
	ProgramAnalysis int `mapstructure:"program_analysis"`
	Recon           int `mapstructure:"recon"`
	VulnDetection   int `mapstructure:"vuln_detection"`
	Validation      int `mapstructure:"validation"`
	ChainDiscovery  int `mapstructure:"chain_discovery"`
	Reporting       int `mapstructure:"reporting"`
	Strategy        int `mapstructure:"strategy"`
}

type PricingConfig struct {
	HaikuInput          float64 `mapstructure:"haiku_input"`
	HaikuOutput         float64 `mapstructure:"haiku_output"`
	SonnetInput         float64 `mapstructure:"sonnet_input"`
	SonnetOutput        float64 `mapstructure:"sonnet_output"`
	OpusInput           float64 `mapstructure:"opus_input"`
	OpusOutput          float64 `mapstructure:"opus_output"`
	CacheReadMultiplier float64 `mapstructure:"cache_read_multiplier"`
}

// ScanConfig holds scanning engine settings.
type ScanConfig struct {
	TargetRateLimit TargetRateLimitConfig      `mapstructure:"target_rate_limit"`
	Timeouts        map[string]int             `mapstructure:"timeouts"`
	Nuclei          NucleiConfig               `mapstructure:"nuclei"`
	Ffuf            FfufConfig                 `mapstructure:"ffuf"`
	Masscan         MasscanConfig              `mapstructure:"masscan"`
	Nmap            NmapConfig                 `mapstructure:"nmap"`
	Katana          KatanaConfig               `mapstructure:"katana"`
}

type TargetRateLimitConfig struct {
	RequestsPerSecond int `mapstructure:"requests_per_second"`
	Burst             int `mapstructure:"burst"`
	MinRPS            int `mapstructure:"min_rps"`
	MaxRPS            int `mapstructure:"max_rps"`
}

type NucleiConfig struct {
	Severity     string `mapstructure:"severity"`
	RateLimit    int    `mapstructure:"rate_limit"`
	BulkSize     int    `mapstructure:"bulk_size"`
	TemplatesDir string `mapstructure:"templates_dir"`
}

type FfufConfig struct {
	Threads  int    `mapstructure:"threads"`
	Rate     int    `mapstructure:"rate"`
	Wordlist string `mapstructure:"wordlist"`
}

type MasscanConfig struct {
	Rate  int    `mapstructure:"rate"`
	Ports string `mapstructure:"ports"`
}

type NmapConfig struct {
	TopPorts int    `mapstructure:"top_ports"`
	Scripts  string `mapstructure:"scripts"`
}

type KatanaConfig struct {
	Depth       int  `mapstructure:"depth"`
	JSCrawl     bool `mapstructure:"js_crawl"`
	MaxDuration int  `mapstructure:"max_duration"`
}

// PreprocessorConfig controls data reduction pipeline.
type PreprocessorConfig struct {
	MaxOutputBytes   int             `mapstructure:"max_output_bytes"`
	SimhashThreshold int             `mapstructure:"simhash_threshold"`
	Filter           FilterConfig    `mapstructure:"filter"`
	ArrayTruncation  ArrayTruncConfig `mapstructure:"array_truncation"`
}

type FilterConfig struct {
	RemoveStatusCodes   []int `mapstructure:"remove_status_codes"`
	RemoveDefaultPages  bool  `mapstructure:"remove_default_pages"`
	RemoveClosedPorts   bool  `mapstructure:"remove_closed_ports"`
	RemoveStandardHdrs  bool  `mapstructure:"remove_standard_headers"`
}

type ArrayTruncConfig struct {
	MaxItems int `mapstructure:"max_items"`
}

// DBConfig holds PostgreSQL settings.
type DBConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Name     string `mapstructure:"name"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	PoolMin  int    `mapstructure:"pool_min"`
	PoolMax  int    `mapstructure:"pool_max"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// DSN returns a PostgreSQL connection string.
func (d DBConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode,
	)
}

// RedisConfig holds Redis settings.
type RedisConfig struct {
	Address        string `mapstructure:"address"`
	Password       string `mapstructure:"password"`
	DB             int    `mapstructure:"db"`
	MaxMemory      string `mapstructure:"max_memory"`
	EvictionPolicy string `mapstructure:"eviction_policy"`
}

// NATSConfig holds NATS JetStream settings.
type NATSConfig struct {
	URL                  string            `mapstructure:"url"`
	MaxReconnect         int               `mapstructure:"max_reconnect"`
	ReconnectWaitSeconds int               `mapstructure:"reconnect_wait_seconds"`
	Streams              map[string]StreamConfig `mapstructure:"streams"`
}

func (n NATSConfig) ReconnectWait() time.Duration {
	return time.Duration(n.ReconnectWaitSeconds) * time.Second
}

type StreamConfig struct {
	Retention  string `mapstructure:"retention"`
	MaxMsgs    int64  `mapstructure:"max_msgs"`
	MaxAgeDays int    `mapstructure:"max_age_days"`
}

// RunConfig holds runtime settings.
type RunConfig struct {
	MaxDurationHours           int `mapstructure:"max_duration_hours"`
	CheckpointIntervalSeconds  int `mapstructure:"checkpoint_interval_seconds"`
	MaxTargetsPerRun           int `mapstructure:"max_targets_per_run"`
	ConcurrentScanners         int `mapstructure:"concurrent_scanners"`
	ConcurrentSolvers          int `mapstructure:"concurrent_solvers"`
}

func (r RunConfig) MaxDuration() time.Duration {
	return time.Duration(r.MaxDurationHours) * time.Hour
}

func (r RunConfig) CheckpointInterval() time.Duration {
	return time.Duration(r.CheckpointIntervalSeconds) * time.Second
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
}

// Load reads config from file and environment variables.
func Load(path string) (*Config, error) {
	v := viper.New()

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("./configs")
		v.AddConfigPath(".")
	}

	// Environment variable overrides: AIBBP_DATABASE_HOST, etc.
	v.SetEnvPrefix("AIBBP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Override password from env if set
	if pw := os.Getenv("AIBBP_DB_PASSWORD"); pw != "" {
		v.Set("database.password", pw)
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}
