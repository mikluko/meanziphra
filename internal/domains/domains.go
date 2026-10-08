// Package domains приводит DNS-имена из сертификатов к списку для name constraints.
package domains

import (
	"slices"
	"strings"
)

// Normalize приводит имя из SAN к виду для name constraints: нижний регистр, без "*." в начале.
// ok ложно, если имя не годится в ограничение: одна метка, пустые метки, символы вне [a-z0-9-],
// "*" не в начале или метка, которая начинается или кончается дефисом.
func Normalize(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	name = strings.TrimPrefix(name, "*.")
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", false
			}
		}
	}
	return name, true
}

// TLD возвращает последнюю метку имени.
func TLD(name string) string {
	return name[strings.LastIndexByte(name, '.')+1:]
}

// Minimize убирает имена, которые уже покрывает их предок из того же списка, и возвращает остальные по алфавиту.
// Для name constraints это тот же набор: ограничение sberbank.ru разрешает и online.sberbank.ru.
func Minimize(names []string) []string {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	var r []string
	for n := range set {
		if !covered(n, set) {
			r = append(r, n)
		}
	}
	slices.Sort(r)
	return r
}

func covered(name string, set map[string]bool) bool {
	for i := strings.IndexByte(name, '.'); i >= 0; {
		parent := name[i+1:]
		if set[parent] {
			return true
		}
		j := strings.IndexByte(parent, '.')
		if j < 0 {
			return false
		}
		i += j + 1
	}
	return false
}

// Zones возвращает зоны верхнего уровня имён names по алфавиту, без повторов.
func Zones(names []string) []string {
	var r []string
	for _, n := range names {
		r = append(r, TLD(n))
	}
	slices.Sort(r)
	return slices.Compact(r)
}
