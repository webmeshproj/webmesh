//go:build !wasm

/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package services contains the gRPC server for inter-node communication.
package services

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	promapi "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

func startMetricsServer(log *slog.Logger, listenAddr string, path string) {
	go func() {
		log.Info(fmt.Sprintf("Starting HTTP metrics server on %s", listenAddr))
		http.Handle(path, promhttp.Handler())
		if err := http.ListenAndServe(listenAddr, nil); err != nil {
			log.Error("metrics server failed", slog.String("error", err.Error()))
		}
	}()
}

func appendMetricsMiddlewares(log *slog.Logger, uu []grpc.UnaryServerInterceptor, ss []grpc.StreamServerInterceptor) ([]grpc.UnaryServerInterceptor, []grpc.StreamServerInterceptor, error) {
	log.Debug("registering gRPC metrics interceptors")
	metrics := prometheus.NewServerMetrics(prometheus.WithServerHandlingTimeHistogram())
	uu = append(uu, metrics.UnaryServerInterceptor())
	ss = append(ss, metrics.StreamServerInterceptor())
	if err := promapi.Register(metrics); err != nil {
		return nil, nil, err
	}
	return uu, ss, nil
}
