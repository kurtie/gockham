package gockham

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Number interface {
	int | float64
}

func Min[T Number](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func Max[T Number](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func TernOp[T any](cond bool, trueRes T, falseRes T) T {
	if cond {
		return trueRes
	}
	return falseRes
}

func UpcaseInitial(str string) string {
	for i, v := range str {
		return string(unicode.ToUpper(v)) + str[i+1:]
	}
	return ""
}

func StrToIntArray(line string) []int {
	parts := strings.Split(line, ",")
	ret := make([]int, len(parts))
	for i, part := range parts {
		ret[i], _ = strconv.Atoi(part)
	}
	return ret
}

func IntArrToStr(a []int, delim string) string {
	return strings.Trim(strings.Replace(fmt.Sprint(a), " ", delim, -1), "[]")
}

func StrArrayContains(arr []string, str string) bool {
	for _, s := range arr {
		if s == str {
			return true
		}
	}
	return false
}

// ArrayIndexOf returns the index of the first occurrence of element in the array or -1 if not found
func ArrayIndexOf[T comparable](arr []T, val T) int {
	for idx, item := range arr {
		if item == val {
			return idx
		}
	}
	return -1
}

// ArrayContains returns true if the array contains the element
func ArrayContains[T comparable](arr []T, val T) bool {
	return ArrayIndexOf(arr, val) != -1
}

func ArrayRemove[T any](a []T, i int) []T {
	length := len(a) - 1
	if length < 0 {
		return []T{}
	}
	a[i] = a[length]
	return a[:length]
}

func UnmarshalledJsonToIntArray(obj interface{}) []int {
	arr := obj.([]interface{})
	ret := make([]int, len(arr))
	for idx, f := range arr {
		ret[idx] = int(f.(float64))
	}
	return ret
}

func GetReflectField(instance interface{}, field string) reflect.Value {
	return reflect.ValueOf(instance).Elem().FieldByName(field)
}

// Casts a interface to bool. If nil returns false
func CastBool(value interface{}) bool {
	if value == nil {
		return false
	}
	return value.(bool)
}

// Casts a value to a type T. If nil returns empty type value
func Cast[T any](value any) T {
	if value == nil {
		var zero T
		return zero
	}
	return value.(T)
}

// Casts a value to map[K]V. If nil returns an empty map
func CastMap[K comparable, V any](value any) map[K]V {
	if value == nil {
		return map[K]V{}
	}
	return value.(map[K]V)
}

// Casts a value to an array of type T. If nil returns an empty array
func CastArray[T any](value any) []T {
	if value == nil {
		return []T{}
	}
	switch x := value.(type) {
	// If it is a slice of any, convert to slice of T
	case []any:
		ret := make([]T, len(x))
		for idx, f := range x {
			ret[idx] = f.(T)
		}
		return ret
	// Otherwise try to cast the entire array
	default:
		return value.([]T)
	}
}

func IntFromMap(m map[string]any, k string) int {
	val := m[k]
	if val != nil {
		// Some go versions is a float64, some are a json.Number
		switch v := val.(type) {
		case float64:
			return int(v)
		case json.Number:
			i, _ := v.Int64()
			return int(i)
		}
	}
	return 0
}

/* If err is nil, executes action and returns its error. Otherwise, returns err */
func ChainErr(err error, action func() error) error {
	if err != nil {
		return err
	}
	return action()
}

func GetNowPtr() *time.Time {
	now := time.Now()
	return &now
}
