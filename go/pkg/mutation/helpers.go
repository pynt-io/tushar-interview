package mutation

import (
	"fmt"
	"strconv"
)

// toStr renders a value as a string for storage in string-typed request maps.
func toStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// toInt coerces a value to an int, supporting the common types a value may
// arrive as (int, YAML-decoded float64, or a numeric string).
func toInt(v any) (int, error) {
	switch x := v.(type) {
	case int:
		return x, nil
	case int64:
		return int(x), nil
	case float64:
		return int(x), nil
	case string:
		return strconv.Atoi(x)
	default:
		return 0, fmt.Errorf("cannot convert %T (%v) to int", v, v)
	}
}
