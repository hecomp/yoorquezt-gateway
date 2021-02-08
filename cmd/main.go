package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	consulsd "github.com/go-kit/kit/sd/consul"
	"github.com/gorilla/mux"
	"github.com/hashicorp/consul/api"
	//stdopentracing "github.com/opentracing/opentracing-go"
	//stdzipkin "github.com/openzipkin/zipkin-go"
	//"google.golang.org/grpc"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd"
	"github.com/go-kit/kit/sd/lb"
	httptransport "github.com/go-kit/kit/transport/http"
)

const (
	SignupPath = "/api/auth/v1/signup"
	LoginPath = "/api/auth/v1/login"
	VerifyMailPath = "/api/auth/v1/verify/mail"
	VerifyPasswordResetPath = "/api/auth/v1/verify/password-reset"
)

func main() {
	var (
		httpAddr     = flag.String("http.addr", ":8000", "Address for HTTP (JSON) server")
		consulAddr   = flag.String("consul.addr", ":8500", "Consul agent address")
		retryMax     = flag.Int("retry.max", 3, "per-request retries to different instances")
		retryTimeout = flag.Duration("retry.timeout", 500*time.Millisecond, "per-request timeout, including retries")
	)
	flag.Parse()

	// Logging domain.
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	// Service discovery domain. In this example we use Consul.
	var client consulsd.Client
	{
		consulConfig := api.DefaultConfig()
		if len(*consulAddr) > 0 {
			consulConfig.Address = *consulAddr
		}
		consulClient, err := api.NewClient(consulConfig)
		if err != nil {
			logger.Log("err", err)
			os.Exit(1)
		}
		client = consulsd.NewClient(consulClient)
	}

	// Transport domain.
	//tracer := stdopentracing.GlobalTracer() // no-op
	//zipkinTracer, _ := stdzipkin.NewTracer(nil, stdzipkin.WithNoopTracer(true))
	ctx := context.Background()
	r := mux.NewRouter()

	// Now we begin installing the routes. Each route corresponds to a single
	// method: signup, login.

	// yoorqueztauthsvc routes.
	{
		// addsvc had lots of nice importable Go packages we could leverage.
		// With yoorqueztauthsvc we are not so fortunate, it just has some endpoints
		// that we assume will exist. So we have to write that logic here. This
		// is by design, so you can see two totally different methods of
		// proxying to a remote service.

		var (
			tags        = []string{}
			passingOnly = true
			uppercase   endpoint.Endpoint
			count       endpoint.Endpoint
			instancer   = consulsd.NewInstancer(client, logger, "yoorqueztauthsvc", tags, passingOnly)
		)
		{
			factory := yoorqueztauthsvcFactory(ctx, "POST", SignupPath)
			endpointer := sd.NewEndpointer(instancer, factory, logger)
			balancer := lb.NewRoundRobin(endpointer)
			retry := lb.Retry(*retryMax, *retryTimeout, balancer)
			uppercase = retry
		}
		{
			factory := yoorqueztauthsvcFactory(ctx, "POST", LoginPath)
			endpointer := sd.NewEndpointer(instancer, factory, logger)
			balancer := lb.NewRoundRobin(endpointer)
			retry := lb.Retry(*retryMax, *retryTimeout, balancer)
			count = retry
		}
		{
			factory := yoorqueztauthsvcFactory(ctx, "POST", VerifyMailPath)
			endpointer := sd.NewEndpointer(instancer, factory, logger)
			balancer := lb.NewRoundRobin(endpointer)
			retry := lb.Retry(*retryMax, *retryTimeout, balancer)
			count = retry
		}
		{
			factory := yoorqueztauthsvcFactory(ctx, "POST", VerifyPasswordResetPath)
			endpointer := sd.NewEndpointer(instancer, factory, logger)
			balancer := lb.NewRoundRobin(endpointer)
			retry := lb.Retry(*retryMax, *retryTimeout, balancer)
			count = retry
		}

		// We can use the transport/http.Server to act as our handler, all we
		// have to do provide it with the encode and decode functions for our
		// yoorqueztauthsvc methods.

		r.Handle("/yoorqueztauthsvc/api/auth/v1/signup", httptransport.NewServer(uppercase, decodeSignupRequest, encodeJSONResponse))
		r.Handle("/yoorqueztauthsvc/api/auth/v1/login", httptransport.NewServer(count, decodeLoginRequest, encodeJSONResponse))
		r.Handle("/yoorqueztauthsvc/api/auth/v1/verify/mail", httptransport.NewServer(count, decodeVerifyMailRequest, encodeJSONResponse))
		r.Handle("/yoorqueztauthsvc/api/auth/v1/verify/password-reset", httptransport.NewServer(count, decodeVerifyPasswordResetRequest, encodeJSONResponse))
	}

	// Interrupt handler.
	errc := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	// HTTP transport.
	go func() {
		logger.Log("transport", "HTTP", "addr", *httpAddr)
		errc <- http.ListenAndServe(*httpAddr, r)
	}()

	// Run!
	logger.Log("exit", <-errc)
}

func yoorqueztauthsvcFactory(ctx context.Context, method, path string) sd.Factory {
	return func(instance string) (endpoint.Endpoint, io.Closer, error) {
		if !strings.HasPrefix(instance, "http") {
			instance = "http://" + instance
		}
		tgt, err := url.Parse(instance)
		if err != nil {
			return nil, nil, err
		}
		tgt.Path = path

		// Since yoorqueztauthsvc doesn't have any kind of package we can import, or
		// any formal spec, we are forced to just assert where the endpoints
		// live, and write our own code to encode and decode requests and
		// responses. Ideally, if you write the service, you will want to
		// provide stronger guarantees to your clients.

		var (
			enc httptransport.EncodeRequestFunc
			dec httptransport.DecodeResponseFunc
		)
		switch path {
		case LoginPath:
			enc, dec = encodeJSONRequest, decodeSignupResponse
		case SignupPath:
			enc, dec = encodeJSONRequest, decodeLoginResponse
		case VerifyMailPath:
			enc, dec = encodeJSONRequest, decodeVerifyMailResponse
		case VerifyPasswordResetPath:
			enc, dec = encodeJSONRequest, decodeVerifyPasswordResetResponse
		default:
			return nil, nil, fmt.Errorf("unknown yoorqueztauthsvc path %q", path)
		}

		return httptransport.NewClient(method, tgt, enc, dec).Endpoint(), nil, nil
	}
}

func encodeJSONResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

func encodeJSONRequest(_ context.Context, req *http.Request, request interface{}) error {
	// Both uppercase and count requests are encoded in the same way:
	// simple JSON serialization to the request body.
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(request); err != nil {
		return err
	}
	req.Body = ioutil.NopCloser(&buf)
	return nil
}

func decodeSignupResponse(ctx context.Context, resp *http.Response) (interface{}, error) {
	var response struct {
		Status  bool        `json:"status"`
		Message string   `json:",omitempty"`
		Data    interface{} `json:"data"`
		Err     error `json:"err,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func decodeLoginResponse(ctx context.Context, resp *http.Response) (interface{}, error) {
	var response struct {
		Status  bool        `json:"status"`
		Message string   `json:",omitempty"`
		Data    interface{} `json:"data"`
		User    interface{} `json:"user"`
		Err     error `json:"err,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func decodeVerifyMailResponse(ctx context.Context, resp *http.Response) (interface{}, error) {
	var response struct {
		Status  bool        `json:"status"`
		Message string   `json:",omitempty"`
		Data    interface{} `json:"data"`
		Err     error `json:"err,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func decodeVerifyPasswordResetResponse(ctx context.Context, resp *http.Response) (interface{}, error) {
	var response struct {
		Status  bool        `json:"status"`
		Message string   `json:",omitempty"`
		Data    interface{} `json:"data"`
		Err     error `json:"err,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func decodeSignupRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var request struct {
		ID         string    `json:"id" sql:"id"`
		Email      string    `json:"email" validate:"required" sql:"email"`
		Password   string    `json:"password" validate:"required" sql:"password"`
		Username   string    `json:"username" sql:"username"`
		TokenHash  string    `json:"tokenhash" sql:"tokenhash"`
		IsVerified bool      `json:"isverified" sql:"isverified"`
		CreatedAt  time.Time `json:"createdat" sql:"createdat"`
		UpdatedAt  time.Time `json:"updatedat" sql:"updatedat"`
	}
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}

func decodeLoginRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var request struct {
		ID         string    `json:"id" sql:"id"`
		Email      string    `json:"email" validate:"required" sql:"email"`
		Password   string    `json:"password" validate:"required" sql:"password"`
		Username   string    `json:"username" sql:"username"`
		TokenHash  string    `json:"tokenhash" sql:"tokenhash"`
		IsVerified bool      `json:"isverified" sql:"isverified"`
		CreatedAt  time.Time `json:"createdat" sql:"createdat"`
		UpdatedAt  time.Time `json:"updatedat" sql:"updatedat"`
	}
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}

type VerificationDataType int

const (
	MailConfirmation VerificationDataType = iota + 1
	PassReset
)

func decodeVerifyMailRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var request struct {
		Email     string    `json:"email" validate:"required" sql:"email"`
		Code      string    `json:"code" validate:"required" sql:"code"`
		ExpiresAt time.Time `json:"expiresat" sql:"expiresat"`
		Type      VerificationDataType    `json:"type" sql:"type"`
	}
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}

func decodeVerifyPasswordResetRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var request struct {
		Email     string    `json:"email" validate:"required" sql:"email"`
		Code      string    `json:"code" validate:"required" sql:"code"`
		ExpiresAt time.Time `json:"expiresat" sql:"expiresat"`
		Type      VerificationDataType    `json:"type" sql:"type"`
	}
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}
