package client

import (
	"fmt"

	"github.com/alice02/nifcloud-sdk-go/nifcloud"
	"github.com/alice02/nifcloud-sdk-go/nifcloud/client/metadata"
	"github.com/alice02/nifcloud-sdk-go/nifcloud/request"
)

// A Config provides configuration to a service client instance.
type Config struct {
	Config        *nifcloud.Config
	Handlers      request.Handlers
	Endpoint      string
	SigningRegion string
	SigningName   string

	// States that the signing name did not come from a modeled source but
	// was derived based on other data. Used by service client constructors
	// to determine if the signin name can be overriden based on metadata the
	// service has.
	SigningNameDerived bool
}

// ConfigProvider provides a generic way for a service client to receive
// the ClientConfig without circular dependencies.
type ConfigProvider interface {
	ClientConfig(serviceName string, cfgs ...*nifcloud.Config) Config
}

// ConfigNoResolveEndpointProvider same as ConfigProvider except it will not
// resolve the endpoint automatically. The service client's endpoint must be
// provided via the nifcloud.Config.Endpoint field.
type ConfigNoResolveEndpointProvider interface {
	ClientConfigNoResolveEndpoint(cfgs ...*nifcloud.Config) Config
}

// A Client implements the base client request and response handling
// used by all service clients.
type Client struct {
	request.Retryer
	metadata.ClientInfo

	Config   nifcloud.Config
	Handlers request.Handlers
}

// New will return a pointer to a new initialized service client.
func New(cfg nifcloud.Config, info metadata.ClientInfo, handlers request.Handlers, options ...func(*Client)) *Client {
	svc := &Client{
		Config:     cfg,
		ClientInfo: info,
		Handlers:   handlers.Copy(),
	}

	switch retryer, ok := cfg.Retryer.(request.Retryer); {
	case ok:
		svc.Retryer = retryer
	case cfg.Retryer != nil && cfg.Logger != nil:
		s := fmt.Sprintf("WARNING: %T does not implement request.Retryer; using DefaultRetryer instead", cfg.Retryer)
		cfg.Logger.Log(s)
		fallthrough
	default:
		maxRetries := nifcloud.IntValue(cfg.MaxRetries)
		if cfg.MaxRetries == nil || maxRetries == nifcloud.UseServiceDefaultRetries {
			maxRetries = 3
		}
		svc.Retryer = DefaultRetryer{NumMaxRetries: maxRetries}
	}

	svc.AddDebugHandlers()

	for _, option := range options {
		option(svc)
	}

	return svc
}

// NewRequest returns a new Request pointer for the service API
// operation and parameters.
func (c *Client) NewRequest(operation *request.Operation, params interface{}, data interface{}) *request.Request {
	return request.New(c.Config, c.ClientInfo, c.Handlers, c.Retryer, operation, params, data)
}

// AddDebugHandlers injects debug logging handlers into the service to log request
// debug information.
func (c *Client) AddDebugHandlers() {
	if !c.Config.LogLevel.AtLeast(nifcloud.LogDebug) {
		return
	}

	c.Handlers.Send.PushFrontNamed(request.NamedHandler{Name: "awssdk.client.LogRequest", Fn: logRequest})
	c.Handlers.Send.PushBackNamed(request.NamedHandler{Name: "awssdk.client.LogResponse", Fn: logResponse})
}
