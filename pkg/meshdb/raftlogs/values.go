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
	"database/sql/driver"
	"fmt"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SQLParameterToDriverValue converts a SQLParameter to a driver.Value.
func SQLParameterToDriverValue(param *v1.SQLParameter) (driver.Value, error) {
	if param == nil || param.Type == v1.SQLParameterType_SQL_PARAM_NULL {
		return nil, nil
	}
	switch param.Type {
	case v1.SQLParameterType_SQL_PARAM_INT64:
		return param.GetInt64(), nil
	case v1.SQLParameterType_SQL_PARAM_DOUBLE:
		return param.GetDouble(), nil
	case v1.SQLParameterType_SQL_PARAM_BOOL:
		return param.GetBool(), nil
	case v1.SQLParameterType_SQL_PARAM_BYTES:
		return param.GetBytes(), nil
	case v1.SQLParameterType_SQL_PARAM_STRING:
		return param.GetStr(), nil
	case v1.SQLParameterType_SQL_PARAM_TIME:
		return param.GetTime().AsTime(), nil
	default:
		return nil, fmt.Errorf("unsupported type: %v", param.GetType())
	}
}

// NormalizeRowValues converts a slice of values to a slice of SQLParameters.
func NormalizeRowValues(data []interface{}, types []string) ([]*v1.SQLParameter, error) {
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
