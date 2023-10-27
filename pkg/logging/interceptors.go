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

package logging

import (
	"log/slog"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// ContextUnaryServerInterceptor returns a grpc.UnaryServerInterceptor that logs
// to the given logger.
func ContextUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return logging.UnaryServerInterceptor(
		ContextInterceptor(),
		logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
	)
}

// ContextLogCallsStreamServerInterceptor returns a grpc.UnaryServerInterceptor that logs
// to the given logger.
func ContextStreamServerInterceptor() grpc.StreamServerInterceptor {
	return logging.StreamServerInterceptor(
		ContextInterceptor(),
		logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
	)
}

// ContextInterceptor returns a logging.Logger that logs to the logger provided
// in the context.
func ContextInterceptor() logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		log := context.LoggerFrom(ctx)
		if msg == "started call" {
			msg = "Started gRPC call"
		}
		if msg == "finished call" {
			msg = "Finished gRPC call"
		}
		log.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
