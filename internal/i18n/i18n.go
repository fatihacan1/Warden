// Package i18n holds the languages Warden speaks to end users: the language
// of emails, chosen per user, with a per-instance default.
//
// Adding a language: add it to Locales, add its strings below, and add a
// templates/<code>/ folder to the mailer.
package i18n

import (
	"strconv"
	"strings"
	"time"
)

// Locale is a supported language.
type Locale struct {
	Code string // BCP 47 primary language, e.g. "en"
	Name string // in its own language
	Flag string // emoji, for the admin UI
}

// Default is used when nothing else applies.
const Default = "en"

// Locales lists every supported language.
var Locales = []Locale{
	{"en", "English", "🇬🇧"},
	{"tr", "Türkçe", "🇹🇷"},
}

// Supported reports whether code is a supported locale.
func Supported(code string) bool {
	for _, l := range Locales {
		if l.Code == code {
			return true
		}
	}
	return false
}

// Lookup returns a locale by code, or the default.
func Lookup(code string) Locale {
	for _, l := range Locales {
		if l.Code == code {
			return l
		}
	}
	return Locales[0]
}

// Normalize maps "tr-TR", "TR", "tr_TR" to "tr"; unsupported or empty input
// returns "".
func Normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexAny(tag, "-_"); i > 0 {
		tag = tag[:i]
	}
	if Supported(tag) {
		return tag
	}
	return ""
}

// FromAcceptLanguage picks the best supported locale from an
// Accept-Language header, or "".
func FromAcceptLanguage(header string) string {
	best, bestQ := "", -1.0
	for i, part := range strings.Split(header, ",") {
		if i > 20 {
			break
		}
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		if code := Normalize(tag); code != "" && q > bestQ {
			best, bestQ = code, q
		}
	}
	return best
}

// Duration renders "24 hours" / "24 saat".
func Duration(d time.Duration, locale string) string {
	n, unit := int(d/time.Minute), "minute"
	if d >= time.Hour && d%time.Hour == 0 {
		n, unit = int(d/time.Hour), "hour"
	}
	switch locale {
	case "tr":
		return strconv.Itoa(n) + map[string]string{"minute": " dakika", "hour": " saat"}[unit]
	default:
		if n != 1 {
			unit += "s"
		}
		return strconv.Itoa(n) + " " + unit
	}
}

var trMonths = []string{"Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"}

// Time renders a timestamp in UTC for emails.
func Time(t time.Time, locale string) string {
	t = t.UTC()
	switch locale {
	case "tr":
		return strconv.Itoa(t.Day()) + " " + trMonths[t.Month()-1] + " " + strconv.Itoa(t.Year()) + " " + t.Format("15:04") + " UTC"
	default:
		return t.Format("Mon, 2 Jan 2006 15:04 UTC")
	}
}

var messages = map[string]map[string]string{
	"en": {"password": "Password", "two_factor": "two-factor code", "unknown_device": "Unknown device", "app": "app"},
	"tr": {"password": "Şifre", "two_factor": "iki adımlı doğrulama kodu", "unknown_device": "Bilinmeyen cihaz", "app": "uygulama"},
}

// T returns a short UI string in locale, falling back to English.
func T(locale, key string) string {
	if v, ok := messages[locale][key]; ok {
		return v
	}
	return messages[Default][key]
}
