package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	consulsd "github.com/go-kit/kit/sd/consul"
	"github.com/gorilla/mux"
	"github.com/hashicorp/consul/api"
	stdopentracing "github.com/opentracing/opentracing-go"
	stdzipkin "github.com/openzipkin/zipkin-go"
	"google.golang.org/grpc"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd"
	"github.com/go-kit/kit/sd/lb"
	
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztendpoint"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztservice"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorquezttransport"
)

func main() {
	var (
		httpAddr     = flag.String("http.addr", ":8000", "Address for HTTP (JSON) server")
		consulAddr   = flag.String("consul.addr", "", "Consul agent address")
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
	tracer := stdopentracing.GlobalTracer() // no-op
	zipkinTracer, _ := stdzipkin.NewTracer(nil, stdzipkin.WithNoopTracer(true))
	r := mux.NewRouter()

	// Now we begin installing the routes. Each route corresponds to a single
	// method: sum, concat, uppercase, and count.

	// addsvc routes.
	{
		// Each method gets constructed with a factory. Factories take an
		// instance string, and return a specific endpoint. In the factory we
		// dial the instance string we get from Consul, and then leverage an
		// addsvc client package to construct a complete service. We can then
		// leverage the addsvc.Make{Sum,Concat}Endpoint constructors to convert
		// the complete service to specific endpoint.
		var (
			tags        = []string{}
			passingOnly = true
			endpoints   = yoorqueztendpoint.Set{}
			instancer   = consulsd.NewInstancer(client, logger, "yoorqueztsvc", tags, passingOnly)
		)
		{
			factory := yoorqueztsvcFactory(yoorqueztendpoint.MakeSumEndpoint, tracer, zipkinTracer, logger)
			endpointer := sd.NewEndpointer(instancer, factory, logger)
			balancer := lb.NewRoundRobin(endpointer)
			retry := lb.Retry(*retryMax, *retryTimeout, balancer)
			endpoints.SumEndpoint = retry
		}
		{
			factory := yoorqueztsvcFactory(yoorqueztendpoint.MakeConcatEndpoint, tracer, zipkinTracer, logger)
			endpointer := sd.NewEndpointer(instancer, factory, logger)
			balancer := lb.NewRoundRobin(endpointer)
			retry := lb.Retry(*retryMax, *retryTimeout, balancer)
			endpoints.ConcatEndpoint = retry
		}

		// Here we leverage the fact that yoorqueztsvc comes with a constructor for an
		// HTTP handler, and just install it under a particular path prefix in
		// our router.

		r.PathPrefix("/yoorqueztsvc").Handler(http.StripPrefix("/yoorqueztsvc", yoorquezttransport.NewHTTPHandler(endpoints, tracer, zipkinTracer, logger)))
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

func yoorqueztsvcFactory(makeEndpoint func(yoorqueztservice.Service) endpoint.Endpoint, tracer stdopentracing.Tracer, zipkinTracer *stdzipkin.Tracer, logger log.Logger) sd.Factory {
	return func(instance string) (endpoint.Endpoint, io.Closer, error) {
		// We could just as easily use the HTTP or Thrift client package to make
		// the connection to yoorqueztsvc. We've chosen gRPC arbitrarily. Note that
		// the transport is an implementation detail: it doesn't leak out of
		// this function. Nice!

		conn, err := grpc.Dial(instance, grpc.WithInsecure())
		if err != nil {
			return nil, nil, err
		}
		service := yoorquezttransport.NewGRPCClient(conn, tracer, zipkinTracer, logger)
		endpoint := makeEndpoint(service)

		// Notice that the yoorqueztsvc gRPC client converts the connection to a
		// complete yoorqueztsvc, and we just throw away everything except the method
		// we're interested in. A smarter factory would mux multiple methods
		// over the same connection. But that would require more work to manage
		// the returned io.Closer, e.g. reference counting. Since this is for
		// the purposes of demonstration, we'll just keep it simple.

		return endpoint, conn, nil
	}
}
