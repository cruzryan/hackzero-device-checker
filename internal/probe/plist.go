package probe

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Property lists are read through Apple's own `plutil`, which converts any
// plist (binary or XML) to JSON or XML on stdout. These pure decoders turn that
// output into plain Go values: map[string]any, []any, string, bool, int64,
// float64. Dates become RFC 3339 strings. They carry no build constraint so
// they are unit-tested on every platform.

// decodePlistJSON decodes `plutil -convert json -o - FILE` output.
func decodePlistJSON(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	root, ok := normalizeJSON(value).(map[string]any)
	if !ok {
		return nil, errors.New("plist root is not a dictionary")
	}
	return root, nil
}

func normalizeJSON(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			v[key] = normalizeJSON(item)
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = normalizeJSON(item)
		}
		return v
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		f, _ := v.Float64()
		return f
	default:
		return v
	}
}

// decodePlistXML decodes `plutil -convert xml1 -o - FILE` output. It is the
// fallback for plists holding types (dates, data) that JSON conversion refuses.
func decodePlistXML(data []byte) (map[string]any, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local == "plist" {
			continue
		}
		value, err := plistValue(decoder, start)
		if err != nil {
			return nil, err
		}
		root, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("plist root is not a dictionary")
		}
		return root, nil
	}
}

func plistValue(decoder *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		result := map[string]any{}
		key := ""
		haveKey := false
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch t := token.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					text, err := plistText(decoder)
					if err != nil {
						return nil, err
					}
					key, haveKey = text, true
					continue
				}
				value, err := plistValue(decoder, t)
				if err != nil {
					return nil, err
				}
				if !haveKey {
					return nil, errors.New("plist dict value without key")
				}
				result[key] = value
				haveKey = false
			case xml.EndElement:
				return result, nil
			}
		}
	case "array":
		result := []any{}
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch t := token.(type) {
			case xml.StartElement:
				value, err := plistValue(decoder, t)
				if err != nil {
					return nil, err
				}
				result = append(result, value)
			case xml.EndElement:
				return result, nil
			}
		}
	case "true", "false":
		if err := decoder.Skip(); err != nil {
			return nil, err
		}
		return start.Name.Local == "true", nil
	case "integer":
		text, err := plistText(decoder)
		if err != nil {
			return nil, err
		}
		return strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	case "real":
		text, err := plistText(decoder)
		if err != nil {
			return nil, err
		}
		return strconv.ParseFloat(strings.TrimSpace(text), 64)
	case "string", "date", "data":
		text, err := plistText(decoder)
		return strings.TrimSpace(text), err
	default:
		return nil, fmt.Errorf("unsupported plist element %q", start.Name.Local)
	}
}

// plistText reads character data up to the matching end element.
func plistText(decoder *xml.Decoder) (string, error) {
	var builder strings.Builder
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return "", io.ErrUnexpectedEOF
		}
		if err != nil {
			return "", err
		}
		switch t := token.(type) {
		case xml.CharData:
			builder.Write(t)
		case xml.EndElement:
			return builder.String(), nil
		}
	}
}

// plistBool reads a boolean-ish plist value: a bool, a non-zero number, or a
// "1"/"0"/"true"/"false"/"yes"/"no" string. ok is false when absent or odd.
func plistBool(dict map[string]any, key string) (value bool, ok bool) {
	raw, present := dict[key]
	if !present {
		return false, false
	}
	switch v := raw.(type) {
	case bool:
		return v, true
	case int64:
		return v != 0, true
	case float64:
		return v != 0, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes":
			return true, true
		case "0", "false", "no":
			return false, true
		}
	}
	return false, false
}

// plistInt reads an integer plist value (or a numeric string).
func plistInt(dict map[string]any, key string) (int, bool) {
	switch v := dict[key].(type) {
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(v))
		return i, err == nil
	}
	return 0, false
}

// plistString reads a string (numbers are formatted, so a "Display Version"
// stored as the integer 27 still reads as "27").
func plistString(dict map[string]any, key string) string {
	switch v := dict[key].(type) {
	case string:
		return v
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// parsePlistDate accepts the RFC 3339 form produced by plutil and the
// `defaults read` form "2026-09-15 01:36:31 +0000".
func parsePlistDate(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05 -0700"} {
		if t, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
