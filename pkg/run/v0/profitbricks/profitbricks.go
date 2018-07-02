package profitbricks

import (
	"os"

	"github.com/docker/infrakit/pkg/launch/inproc"
	logutil "github.com/docker/infrakit/pkg/log"
	"github.com/docker/infrakit/pkg/plugin"
	pb_instance "github.com/docker/infrakit/pkg/provider/profitbricks/plugin/instance"
	"github.com/docker/infrakit/pkg/run"
	"github.com/docker/infrakit/pkg/run/local"
	"github.com/docker/infrakit/pkg/run/scope"
	"github.com/docker/infrakit/pkg/types"
)

const (
	// Kind is the canonical name of the plugin for starting up, etc.
	Kind = "profitbricks"

	// EnvDir is the ProfitBricks directory
	EnvDir = "INFRAKIT_PROFITBRICKS_DIR"

	// EnvEndpoint is the base endpoint for ProfitBricks requests
	EnvEndpoint = "INFRAKIT_PROFITBRICKS_ENDPOINT"

	// EnvUsername is the username for ProfitBricks
	EnvUsername = "INFRAKIT_PROFITBRICKS_USERNAME"

	// EnvPassword is the password for ProfitBricks
	EnvPassword = "INFRAKIT_PROFITBRICKS_PASSWORD"
)

var (
	log = logutil.New("module", "run/v0/profitbricks")
)

func init() {
	inproc.Register(Kind, Run, DefaultOptions)
}

// Options capture the options for starting up the plugin.
type Options struct {
	// Dir is the ProfitBricks directory
	Dir string

	// Username is the username for ProfitBricks
	Username string

	// Password is the password for ProfitBricks
	Password string

	// Endpoint is base URI to connect to ProfitBricks
	Endpoint string
}

func defaultDir() string {
	dir := os.Getenv("INFRAKIT_PROFITBRICKS_DIR")
	if dir != "" {
		return dir
	}
	return os.TempDir()
}

// DefaultOptions return an Options with default values filled in.
var DefaultOptions = Options{
	Endpoint: local.Getenv(EnvEndpoint, ""),
	Dir:      local.Getenv(EnvDir, defaultDir()),
	Username: local.Getenv(EnvUsername, ""),
	Password: local.Getenv(EnvPassword, ""),
}

// Run runs the plugin, blocking the current thread.  Error is returned immediately
// if the plugin cannot be started.
func Run(scope scope.Scope, name plugin.Name,
	config *types.Any) (transport plugin.Transport, impls map[run.PluginCode]interface{}, onStop func(), err error) {

	options := DefaultOptions
	err = config.Decode(&options)
	if err != nil {
		return
	}

	transport.Name = name
	impls = map[run.PluginCode]interface{}{
		run.Instance: pb_instance.NewInstancePlugin(options.Username, options.Password, options.Endpoint, options.Dir),
	}
	return
}
