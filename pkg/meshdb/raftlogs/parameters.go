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

package raftlogs

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ValuesToNamedValues converts a slice of values to a slice of NamedValues.
func ValuesToNamedValues(args []driver.Value) []driver.NamedValue {
	named := make([]driver.NamedValue, len(args))
	for i, arg := range args {
		named[i] = driver.NamedValue{
			Ordinal: i + 1,
			Value:   arg,
		}
	}
	return named
}

// NamedValuesToSQLParameters converts a slice of NamedValues to a slice of SQLParameters.
func NamedValuesToSQLParameters(values []driver.NamedValue) ([]*v1.SQLParameter, error) {
	params := make([]*v1.SQLParameter, len(values))
	for i, argz := range values {
		arg := argz
		sqlParam := &v1.SQLParameter{Name: arg.Name}
		switch v := arg.Value.(type) {
		case nil:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_NULL
		case bool:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_BOOL
			sqlParam.Bool = v
		case int:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_INT64
			sqlParam.Int64 = int64(v)
		case int64:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_INT64
			sqlParam.Int64 = v
		case float64:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_DOUBLE
			sqlParam.Double = v
		case string:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_STRING
			sqlParam.Str = v
		case []byte:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_BYTES
			sqlParam.Bytes = v
		case time.Time:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_TIME
			sqlParam.Time = timestamppb.New(v)
		default:
			return nil, fmt.Errorf("unsupported parameter type: %T", v)
		}
		params[i] = sqlParam
	}
	return params, nil
}

// SQLParametersToNamedArgs converts a slice of SQLParameters to a slice of NamedArgs.
func SQLParametersToNamedArgs(params []*v1.SQLParameter) ([]any, error) {
	if params == nil {
		return nil, nil
	}
	values := make([]any, len(params))
	for idx, param := range params {
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
