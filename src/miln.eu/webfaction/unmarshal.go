// Copyright 2017 Graham Miln, https://miln.eu. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webfaction

import (
	"fmt"
	"reflect"

	"github.com/mitchellh/mapstructure"
)

func Unmarshal(r []interface{}, params ...interface{}) error {
	// XML-RPC always returns an array, within the array are parameters of various types
	if len(r) != 1 {
		return fmt.Errorf("Response root must be an single item array; got: %v", r)
	}
	ra, ok := r[0].([]interface{})
	if !ok {
		return fmt.Errorf("Response root must contain an array; got: %v", r[0])
	}

	for i, p := range params {
		a := ra[i]

		pt := reflect.TypeOf(p)
		if pt.Kind() != reflect.Ptr {
			return fmt.Errorf("Response arguments must by pointers. Item %d is a %s", i, pt.Kind().String())
		}
		pte := pt.Elem()

		at := reflect.TypeOf(a)
		//fmt.Printf("[%d] expect: %v, got: %v\n", i, pte, at)

		switch at.Kind() {
		case pte.Kind():
			// caller's parameter and XML-RPC response type match
			pv := reflect.ValueOf(p)
			if !pv.Elem().CanSet() {
				return fmt.Errorf("Unable to return response arguments. Augment %i can not be modified.", i, pv.Elem().String())
			}
			pv.Elem().Set(reflect.ValueOf(a))
		case reflect.Map:
			if pte.Kind() == reflect.Slice {
				if err := mapstructure.Decode(ra[i:], p); err != nil {
					return fmt.Errorf("Response argument %d array of maps decoded failed: %s", i, err)
				}
			} else {
				if err := mapstructure.Decode(a, p); err != nil {
					return fmt.Errorf("Response argument %d map decoded failed: %s", i, err)
				}
			}
		case reflect.Array:
			fmt.Printf("Response argument %d is an array\n", i, at.Kind().String())
		default:
			fmt.Printf("Response argument %d is unsupported kind: %s\n", i, at.Kind().String())
		}
	}

	return nil
}
