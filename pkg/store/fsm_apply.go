/*
Copyright 2023.

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

package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/raft"
	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.com/webmesh/node/pkg/models/raftdb"
)

// apply executes the operations in a Raft log entry.
func (s *store) apply(l *raft.Log, cmd *v1.RaftLogEntry, log *slog.Logger, startedAt time.Time) *v1.RaftApplyResponse {
	s.dataMux.Lock()
	defer s.dataMux.Unlock()

	var ctx context.Context
	var cancel context.CancelFunc
	if s.opts.ApplyTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), s.opts.ApplyTimeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	// TODO: Really any database operation failing would be a serious condition
	// needing to be handled. For now, we just log the error and return.

	switch cmd.GetType() {
	case v1.RaftCommandType_QUERY:
		log.Debug("applying query",
			slog.String("query", cmd.GetSqlQuery().GetStatement().GetSql()))
		res := s.applyQuery(ctx, log, cmd.GetSqlQuery(), startedAt)
		if res.GetError() != "" {
			log.Error("apply query failed", slog.String("error", res.GetError()))
		} else if res.GetQueryResult().GetError() != "" {
			log.Error("apply query failed", slog.String("error", res.GetQueryResult().GetError()))
		}
		return res
	case v1.RaftCommandType_EXECUTE:
		log.Debug("applying execute",
			slog.String("execute", cmd.GetSqlExec().GetStatement().GetSql()))
		res := s.applyExecute(ctx, log, cmd.GetSqlExec(), startedAt)
		if res.GetError() != "" {
			log.Error("apply query failed", slog.String("error", res.GetError()))
		} else if res.GetExecResult().GetError() != "" {
			log.Error("apply query failed", slog.String("error", res.GetExecResult().GetError()))
		}
		return res
	default:
		log.Error("unknown raft command type",
			slog.String("type", cmd.GetType().String()))
		return &v1.RaftApplyResponse{
			Time:  time.Since(startedAt).String(),
			Error: fmt.Sprintf("unknown raft command type: %s", cmd.GetType()),
		}
	}
}

// applyQuery executes a query.
func (s *store) applyQuery(ctx context.Context, log *slog.Logger, cmd *v1.SQLQuery, startedAt time.Time) *v1.RaftApplyResponse {
	conn, errRes := s.acquireConn(ctx, startedAt)
	if errRes != nil {
		return errRes
	}
	defer conn.Close()
	var querier raftdb.DBTX
	var tx *sql.Tx
	if cmd.Transaction {
		tx, errRes = s.newTransaction(ctx, conn, startedAt)
		if errRes != nil {
			return errRes
		}
		defer func() {
			if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
				log.Error("transaction rollback failed", slog.String("error", err.Error()))
			}
		}()
		querier = tx
	} else {
		querier = conn
	}
	result := s.queryWithConn(ctx, querier, cmd, startedAt)
	if tx != nil && result.Error == "" {
		err := tx.Commit()
		if err != nil {
			return newErrorResponse(startedAt, fmt.Sprintf("commit db transaction: %s", err.Error()))
		}
	}
	return &v1.RaftApplyResponse{
		Time:        time.Since(startedAt).String(),
		QueryResult: result,
	}
}

// applyExecute executes an exec.
func (s *store) applyExecute(ctx context.Context, log *slog.Logger, cmd *v1.SQLExec, startedAt time.Time) *v1.RaftApplyResponse {
	conn, errRes := s.acquireConn(ctx, startedAt)
	if errRes != nil {
		return errRes
	}
	defer conn.Close()
	var querier raftdb.DBTX
	var tx *sql.Tx
	if cmd.Transaction {
		tx, errRes = s.newTransaction(ctx, conn, startedAt)
		if errRes != nil {
			return errRes
		}
		defer func() {
			if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
				log.Error("transaction rollback failed", slog.String("error", err.Error()))
			}
		}()
		querier = tx
	} else {
		querier = conn
	}
	result := s.executeWithConn(ctx, querier, cmd, startedAt)
	if tx != nil && result.Error == "" {
		err := tx.Commit()
		if err != nil {
			return newErrorResponse(startedAt, fmt.Sprintf("commit db transaction: %s", err.Error()))
		}
	}
	return &v1.RaftApplyResponse{
		Time:       time.Since(startedAt).String(),
		ExecResult: result,
	}
}

func (s *store) queryWithConn(ctx context.Context, querier raftdb.DBTX, cmd *v1.SQLQuery, startedAt time.Time) *v1.SQLQueryResult {
	txStart := time.Now()
	params, err := parametersToValues(cmd.GetStatement().GetParameters())
	if err != nil {
		return newSQLQueryError(txStart, err.Error())
	}
	rows, err := querier.QueryContext(ctx, cmd.GetStatement().GetSql(), params...)
	if err != nil {
		return newSQLQueryError(txStart, err.Error())
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return newSQLQueryError(txStart, err.Error())
	}
	types, err := rows.ColumnTypes()
	if err != nil {
		return newSQLQueryError(txStart, err.Error())
	}
	dbTypes := make([]string, len(types))
	for i, t := range types {
		dbTypes[i] = strings.ToUpper(t.DatabaseTypeName())
	}

	values := make([]*v1.SQLValues, 0)
	for rows.Next() {
		dest := make([]interface{}, len(columns))
		ptrs := make([]interface{}, len(dest))
		for i := range ptrs {
			ptrs[i] = &dest[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return newSQLQueryError(txStart, err.Error())
		}
		params, err := normalizeRowValues(dest, dbTypes)
		if err != nil {
			return newSQLQueryError(txStart, err.Error())
		}
		values = append(values, &v1.SQLValues{
			Values: params,
		})
	}

	if err := rows.Err(); err != nil {
		return newSQLQueryError(txStart, err.Error())
	}

	return &v1.SQLQueryResult{
		Columns: columns,
		Types:   dbTypes,
		Values:  values,
		Time:    time.Since(txStart).String(),
	}
}

// executeWithConn executes an exec with a connection.
func (s *store) executeWithConn(ctx context.Context, querier raftdb.DBTX, cmd *v1.SQLExec, startedAt time.Time) *v1.SQLExecResult {
	txStart := time.Now()
	params, err := parametersToValues(cmd.GetStatement().GetParameters())
	if err != nil {
		return newSQLExecError(txStart, err.Error())
	}
	result, err := querier.ExecContext(ctx, cmd.GetStatement().GetSql(), params...)
	if err != nil {
		return newSQLExecError(txStart, err.Error())
	}
	if result == nil {
		return &v1.SQLExecResult{
			Time: time.Since(txStart).String(),
		}
	}
	lastInsertID, err := result.LastInsertId()
	if err != nil {
		return newSQLExecError(txStart, err.Error())
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return newSQLExecError(txStart, err.Error())
	}
	return &v1.SQLExecResult{
		LastInsertId: lastInsertID,
		RowsAffected: rowsAffected,
		Time:         time.Since(txStart).String(),
	}
}

// newTransaction creates a new transaction or returns a result with an error.
func (s *store) newTransaction(ctx context.Context, conn *sql.Conn, startedAt time.Time) (*sql.Tx, *v1.RaftApplyResponse) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, newErrorResponse(startedAt, fmt.Sprintf("begin db transaction: %s", err.Error()))
	}
	return tx, nil
}

// acquireConn acquires a connection from the pool or returns a result with an error.
func (s *store) acquireConn(ctx context.Context, startedAt time.Time) (*sql.Conn, *v1.RaftApplyResponse) {
	conn, err := s.weakData.Conn(ctx)
	if err != nil {
		return nil, newErrorResponse(startedAt, fmt.Sprintf("acquire db connection: %s", err.Error()))
	}
	return conn, nil
}

func newErrorResponse(startedAt time.Time, err string) *v1.RaftApplyResponse {
	return &v1.RaftApplyResponse{
		Time:  time.Since(startedAt).String(),
		Error: err,
	}
}

func newSQLExecError(startedAt time.Time, err string) *v1.SQLExecResult {
	return &v1.SQLExecResult{
		Error: err,
		Time:  time.Since(startedAt).String(),
	}
}

func newSQLQueryError(startedAt time.Time, err string) *v1.SQLQueryResult {
	return &v1.SQLQueryResult{
		Time:  time.Since(startedAt).String(),
		Error: err,
	}
}

// parametersToValues maps values in the proto params to SQL driver values.
func parametersToValues(parameters []*v1.SQLParameter) ([]interface{}, error) {
	if parameters == nil {
		return nil, nil
	}
	values := make([]interface{}, len(parameters))
	for i, param := range parameters {
		switch param.GetType() {
		case v1.SQLParameterType_SQL_PARAM_INT64:
			values[i] = sql.Named(param.GetName(), param.Int64)
		case v1.SQLParameterType_SQL_PARAM_DOUBLE:
			values[i] = sql.Named(param.GetName(), param.Double)
		case v1.SQLParameterType_SQL_PARAM_BOOL:
			values[i] = sql.Named(param.GetName(), param.Bool)
		case v1.SQLParameterType_SQL_PARAM_BYTES:
			values[i] = sql.Named(param.GetName(), param.Bytes)
		case v1.SQLParameterType_SQL_PARAM_STRING:
			values[i] = sql.Named(param.GetName(), param.Str)
		case v1.SQLParameterType_SQL_PARAM_TIME:
			values[i] = sql.Named(param.GetName(), param.Time.AsTime())
		case v1.SQLParameterType_SQL_PARAM_NULL:
			values[i] = sql.Named(param.GetName(), nil)
		default:
			return nil, fmt.Errorf("unsupported type: %T", param.GetType())
		}
	}
	return values, nil
}

// normalizeRowValues performs some normalization of values in the returned rows.
// Text values come over (from sqlite-go) as []byte instead of strings
// for some reason, so we have explicitly converted (but only when type
// is "text" so we don't affect BLOB types)
func normalizeRowValues(data []interface{}, types []string) ([]*v1.SQLParameter, error) {
	values := make([]*v1.SQLParameter, len(types))
	for i, v := range data {
		switch val := v.(type) {
		case int:
			values[i] = &v1.SQLParameter{
				Type:  v1.SQLParameterType_SQL_PARAM_INT64,
				Int64: int64(val),
			}
		case int64:
			values[i] = &v1.SQLParameter{
				Type:  v1.SQLParameterType_SQL_PARAM_INT64,
				Int64: val,
			}
		case float64:
			values[i] = &v1.SQLParameter{
				Type:   v1.SQLParameterType_SQL_PARAM_DOUBLE,
				Double: val,
			}
		case bool:
			values[i] = &v1.SQLParameter{
				Type: v1.SQLParameterType_SQL_PARAM_BOOL,
				Bool: val,
			}
		case string:
			values[i] = &v1.SQLParameter{
				Type: v1.SQLParameterType_SQL_PARAM_STRING,
				Str:  val,
			}
		case []byte:
			if types[i] == "TEXT" {
				values[i] = &v1.SQLParameter{
					Type: v1.SQLParameterType_SQL_PARAM_STRING,
					Str:  string(val),
				}
			} else {
				values[i] = &v1.SQLParameter{
					Type:  v1.SQLParameterType_SQL_PARAM_BYTES,
					Bytes: val,
				}
			}
		case time.Time:
			values[i] = &v1.SQLParameter{
				Type: v1.SQLParameterType_SQL_PARAM_TIME,
				Time: timestamppb.New(val),
			}
		case nil:
			values[i] = &v1.SQLParameter{
				Type: v1.SQLParameterType_SQL_PARAM_NULL,
			}
		default:
			return nil, fmt.Errorf("unhandled column type: %T %v", val, val)
		}
	}
	return values, nil
}
