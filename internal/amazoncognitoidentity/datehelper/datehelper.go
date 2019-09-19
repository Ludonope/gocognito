package datehelper

import (
	"fmt"
	"time"
)

var monthNames = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
var dayNames = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// GetNowString creates a time string with the required formatting
func GetNowString() string {
	now := time.Now().UTC()

	weekDay := dayNames[now.Weekday()]
	month := monthNames[now.Month()-1]
	day := now.Day()

	hours := now.Hour()
	minutes := now.Minute()
	seconds := now.Second()

	year := now.Year()

	return fmt.Sprintf("%s %s %d %02d:%02d:%02d UTC %d", weekDay, month, day, hours, minutes, seconds, year)
}
