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

// Package raftlogs provides facilities for applying raft logs to a database.
package raftlogs

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/models"
)

// Apply applies a raft log to the database.
func Apply(ctx context.Context, db *sql.DB, logEntry *v1.RaftLogEntry) *v1.RaftApplyResponse {
	start := time.Now()
	log := context.LoggerFrom(ctx)
	switch logEntry.GetType() {
	case v1.RaftCommandType_QUERY:
		log.Debug("applying query",
			slog.String("query", logEntry.GetSqlQuery().GetStatement().GetSql()),
			slog.Any("params", logEntry.GetSqlExec().GetStatement().GetParameters()),
		)
		res, err := applyQuery(ctx, db, logEntry.GetSqlQuery())
		if err != nil {
			return &v1.RaftApplyResponse{
				Time:  time.Since(start).String(),
				Error: err.Error(),
			}
		}
		res.Time = time.Since(start).String()
		return res
	case v1.RaftCommandType_EXECUTE:
		log.Debug("applying execute",
			slog.String("execute", logEntry.GetSqlExec().GetStatement().GetSql()),
			slog.Any("params", logEntry.GetSqlExec().GetStatement().GetParameters()),
		)
		res, err := applyExecute(ctx, db, logEntry.GetSqlExec())
		if err != nil {
			return &v1.RaftApplyResponse{
				Time:  time.Since(start).String(),
				Error: err.Error(),
			}
		}
		res.Time = time.Since(start).String()
		return res
	default:
		return &v1.RaftApplyResponse{
			Error: fmt.Sprintf("unknown command type: %s", logEntry.GetType()),
		}
	}
}

func applyQuery(ctx context.Context, db *sql.DB, query *v1.SQLQuery) (*v1.RaftApplyResponse, error) {
	c, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}
	defer c.Close()
	var querier models.DBTX
	querier = c
	var tx *sql.Tx
	if query.Transaction {
		tx, err = c.BeginTx(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("begin transaction: %w", err)
		}
		defer func() {
			if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
				context.LoggerFrom(ctx).Error("transaction rollback failed", slog.String("error", err.Error()))
			}
		}()
		querier = tx
	}
	result, err := queryWithQuerier(ctx, querier, query)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	if err == nil && tx != nil {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit transaction: %w", err)
		}
	}
	return &v1.RaftApplyResponse{
		QueryResult: result,
	}, nil
}

func applyExecute(ctx context.Context, db *sql.DB, exec *v1.SQLExec) (*v1.RaftApplyResponse, error) {
	c, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}
	defer c.Close()
	var querier models.DBTX
	querier = c
	var tx *sql.Tx
	if exec.Transaction {
		tx, err = c.BeginTx(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("begin transaction: %w", err)
		}
		defer func() {
			if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
				context.LoggerFrom(ctx).Error("transaction rollback failed", slog.String("error", err.Error()))
			}
		}()
		querier = tx
	}
	result, err := execWithQuerier(ctx, querier, exec)
	if err != nil {
		return nil, fmt.Errorf("execute: %w", err)
	}
	if err == nil && tx != nil {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit transaction: %w", err)
		}
	}
	return &v1.RaftApplyResponse{
		ExecResult: result,
	}, nil
}

func queryWithQuerier(ctx context.Context, q models.DBTX, query *v1.SQLQuery) (*v1.SQLQueryResult, error) {
	params, err := parametersToValues(query.GetStatement().GetParameters())
	if err != nil {
		return nil, fmt.Errorf("convert parameters: %w", err)
	}
	rows, err := q.QueryContext(ctx, query.GetStatement().GetSql(), params...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("get columns: %w", err)
	}
	types, err := rows.ColumnTypes()
	if err != nil {
		return nil, fmt.Errorf("get column types: %w", err)
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
			return nil, fmt.Errorf("scan row: %w", err)
		}
		params, err := normalizeRowValues(dest, dbTypes)
		if err != nil {
			return nil, fmt.Errorf("normalize row values: %w", err)
		}
		values = append(values, &v1.SQLValues{
			Values: params,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return &v1.SQLQueryResult{
		Columns: columns,
		Types:   dbTypes,
		Values:  values,
	}, nil
}

func execWithQuerier(ctx context.Context, q models.DBTX, exec *v1.SQLExec) (*v1.SQLExecResult, error) {
	params, err := parametersToValues(exec.GetStatement().GetParameters())
	if err != nil {
		return nil, fmt.Errorf("convert parameters: %w", err)
	}
	result, err := q.ExecContext(ctx, exec.GetStatement().GetSql(), params...)
	if err != nil {
		return nil, fmt.Errorf("execute: %w", err)
	}
	if result == nil {
		return &v1.SQLExecResult{}, nil
	}
	lastInsertID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get last insert id: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("get rows affected: %w", err)
	}
	return &v1.SQLExecResult{
		LastInsertId: lastInsertID,
		RowsAffected: rowsAffected,
	}, nil
}

func parametersToValues(parameters []*v1.SQLParameter) ([]interface{}, error) {
	if parameters == nil {
		return nil, nil
	}
	values := make([]interface{}, len(parameters))
	for idx, param := range parameters {
		i := idx
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

func normalizeRowValues(data []interface{}, types []string) ([]*v1.SQLParameter, error) {
	values := make([]*v1.SQLParameter, len(types))
	for idx, v := range data {
		i := idx
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
