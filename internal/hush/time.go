package hush

import (
	"encoding/json"
	"fmt"
	"time"
)

// Some Hush datetimes have no zone; they are UTC.
var timeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999"}

type Time struct{ time.Time }

func (t *Time) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for _, layout := range timeLayouts {
		if parsed, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			t.Time = parsed
			return nil
		}
	}
	return fmt.Errorf("unknown datetime %q", s)
}
